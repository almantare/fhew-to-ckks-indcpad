// What does EvalFHEWtoCKKS actually output as a function of the LWE message?
// Encrypt m = 0..7 (no shift) and print the decrypted CKKS slot.
// If output ~ m  -> it returns the MESSAGE (quotient).  Claim "message channel" holds.
// If output ~ 0 for all m -> it returns the phase RESIDUE (e/Delta). Claim must be rewritten.
#include "openfhe.h"
#include "binfhecontext.h"
#include <iostream>
#include <vector>
#include <cmath>
using namespace lbcrypto;
int main(int argc,char**argv){
    uint32_t pLWE=(argc>1)?std::atoi(argv[1]):256;
    uint32_t slots=64, scaleModSize=59, logQ=28, multDepth=13, ringDim=8192;
    CCParams<CryptoContextCKKSRNS> P; P.SetMultiplicativeDepth(multDepth);
    P.SetScalingModSize(scaleModSize); P.SetScalingTechnique(FIXEDAUTO);
    P.SetSecurityLevel(HEStd_NotSet); P.SetRingDim(ringDim); P.SetBatchSize(slots);
    auto cc=GenCryptoContext(P);
    cc->Enable(PKE);cc->Enable(KEYSWITCH);cc->Enable(LEVELEDSHE);cc->Enable(ADVANCEDSHE);cc->Enable(SCHEMESWITCH);
    auto keys=cc->KeyGen();
    auto ccLWE=std::make_shared<BinFHEContext>(); ccLWE->GenerateBinFHEContext(STD128,false,logQ,0,GINX,false);
    auto lwesk=ccLWE->KeyGen(); uint32_t n=ccLWE->GetParams()->GetLWEParams()->Getn();
    cc->EvalFHEWtoCKKSSetup(ccLWE,slots,logQ); cc->SetBinCCForSchemeSwitch(ccLWE); cc->EvalFHEWtoCKKSKeyGen(keys,lwesk);
    uint64_t Q=1ULL<<logQ; NativeInteger q(Q); int64_t Delta=(int64_t)(Q/pLWE);
    NativeInteger mu=q.ComputeMu(); NativeVector s=lwesk->GetElement(); s.SwitchModulus(q);
    printf("n=%u pLWE=%u Q=2^%u Delta=%lld  (LWE dim from GetA: see below)\n",n,pLWE,logQ,(long long)Delta);

    uint32_t NM=8;
    std::vector<LWECiphertext> ct(slots);
    std::vector<int64_t> etrue(NM);
    for(uint32_t m=0;m<NM;m++){
        auto c=ccLWE->Encrypt(lwesk,m,LARGE_DIM,pLWE,q);
        if(m==0) printf("GetA().GetLength()=%u  (vs Getn()=%u)\n", (unsigned)c->GetA().GetLength(), n);
        const NativeVector&a=c->GetA(); NativeInteger in(0);
        for(uint32_t i=0;i<a.GetLength();i++) in+=a[i].ModMulFast(s[i],q,mu); in.ModEq(q);
        int64_t ph=(((int64_t)c->GetB().ConvertToInt()-(int64_t)in.ConvertToInt())%(int64_t)Q+Q)%(int64_t)Q;
        int64_t e=ph-(int64_t)m*Delta; if(e>(int64_t)Q/2)e-=Q; if(e<-(int64_t)Q/2)e+=Q;
        etrue[m]=e;
        ct[m]=c;
    }
    for(uint32_t i=NM;i<slots;i++) ct[i]=ct[0];
    auto cT=cc->EvalFHEWtoCKKS(ct,slots,slots,pLWE,0,pLWE);
    Plaintext d; cc->Decrypt(keys.secretKey,cT,&d); d->SetLength(slots);
    auto o=d->GetRealPackedValue();
    printf("\n  m   e_true    output      output/m?   (phase=Delta*m+e)\n");
    for(uint32_t m=0;m<NM;m++)
        printf("  %u   %6lld   %12.6f   %s\n",m,(long long)etrue[m],o[m],
               (m>0? (std::fabs(o[m]-(double)m)<0.05?"== m  (MESSAGE)":"!= m"):"-"));
    // also verify LWE decryption agrees
    printf("\nsanity: native FHEW decryption of each ct\n  ");
    for(uint32_t m=0;m<NM;m++){ LWEPlaintext r; ccLWE->Decrypt(lwesk,ct[m],&r,pLWE); printf("%d ",(int)r); }
    printf("\n");
    cc->ClearStaticMapsAndVectors(); return 0;
}
