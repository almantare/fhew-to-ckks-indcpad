// SALVAGE TEST: the attack that is actually admissible in the IND-CPA-D game (Def.5 of 2026/285).
// Oracle D takes a STATE INDEX; state is filled only by Enc and Eval. So:
//   E(0,0) -> LWE ct of 0 (state entry, labels m0=m1=0)
//   SW     -> CKKS entry, label tau(0)=0
//   D      -> returns Dec = 0 + e/Delta  != 0   <-- the IND-CPA-D leak, read directly
// No hand-built ciphertexts, no non-plaintext shifts, no calibration probe.
// Switch output is (p/2pi)*sin(2pi*phase/q); invert it to get e.
#include "openfhe.h"
#include "binfhecontext.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <fstream>
using namespace lbcrypto;

int main(int argc,char**argv){
    uint32_t slots=(argc>1)?std::atoi(argv[1]):512;
    uint32_t scaleModSize=(argc>2)?std::atoi(argv[2]):59;
    uint32_t batches=(argc>3)?std::atoi(argv[3]):1;
    uint64_t tsc=(argc>4)?std::strtoull(argv[4],0,10):1; // admissible: g(m)=t*m mod p
    uint32_t pLWE=(argc>5)?std::atoi(argv[5]):256;
    uint32_t ringDim=(argc>6)?std::atoi(argv[6]):8192;
    uint32_t logQ=28, multDepth=13;
    CCParams<CryptoContextCKKSRNS> P; P.SetMultiplicativeDepth(multDepth);
    P.SetScalingModSize(scaleModSize); P.SetScalingTechnique(FIXEDAUTO);
    P.SetSecurityLevel(HEStd_NotSet); P.SetRingDim(ringDim); P.SetBatchSize(slots);
    uint32_t nfmode=(argc>7)?std::atoi(argv[7]):0;   // 1 = try OpenFHE's real NOISE_FLOODING_DECRYPT
    if(nfmode){ P.SetDecryptionNoiseMode(NOISE_FLOODING_DECRYPT); P.SetExecutionMode(EXEC_EVALUATION);
                P.SetNoiseEstimate( (argc>8)?std::atof(argv[8]) : 40.0 ); }
    auto cc=GenCryptoContext(P);
    cc->Enable(PKE);cc->Enable(KEYSWITCH);cc->Enable(LEVELEDSHE);cc->Enable(ADVANCEDSHE);cc->Enable(SCHEMESWITCH);
    auto keys=cc->KeyGen();
    auto ccLWE=std::make_shared<BinFHEContext>(); ccLWE->GenerateBinFHEContext(STD128,false,logQ,0,GINX,false);
    auto lwesk=ccLWE->KeyGen(); uint32_t n=ccLWE->GetParams()->GetLWEParams()->Getn();
    cc->EvalFHEWtoCKKSSetup(ccLWE,slots,logQ); cc->SetBinCCForSchemeSwitch(ccLWE); cc->EvalFHEWtoCKKSKeyGen(keys,lwesk);
    uint64_t Q=1ULL<<logQ; NativeInteger q(Q);
    NativeInteger mu=q.ComputeMu(); NativeVector s=lwesk->GetElement(); s.SwitchModulus(q);

    std::ofstream csv("equations.csv");
    std::ofstream skf("secret.csv");
    for(uint32_t k=0;k<n;k++){int64_t sv=s[k].ConvertToInt(); if(sv>(int64_t)Q/2)sv-=Q; skf<<sv<<(k+1<n?",":"\n");}
    uint32_t tot_exact=0, tot=0; double tot_ss=0, tot_mx=0;
  for(uint32_t B=0;B<batches;B++){
    // E oracle: slots fresh encryptions of 0  (labels m0=m1=0)
    std::vector<LWECiphertext> ct(slots); std::vector<int64_t> etrue(slots);
    std::vector<NativeVector> Aorig(slots); std::vector<int64_t> Borig(slots);
    for(uint32_t i=0;i<slots;i++){
        ct[i]=ccLWE->Encrypt(lwesk,0,LARGE_DIM,pLWE,q);
        Aorig[i]=ct[i]->GetA(); Borig[i]=ct[i]->GetB().ConvertToInt();   // equation uses these
        if(tsc>1){ // H oracle with g(m) = t*m mod p : scales (a,b) and hence phase -> t*phase
            NativeVector at=ct[i]->GetA();
            for(uint32_t j=0;j<n;j++) at[j]=ct[i]->GetA()[j].ModMul(NativeInteger(tsc),q);
            ct[i]=std::make_shared<LWECiphertextImpl>(at, ct[i]->GetB().ModMul(NativeInteger(tsc),q), NativeInteger(pLWE));
        }
        const NativeVector&a=ct[i]->GetA(); NativeInteger in(0);
        for(uint32_t j=0;j<n;j++) in+=a[j].ModMulFast(s[j],q,mu); in.ModEq(q);
        int64_t e=(((int64_t)ct[i]->GetB().ConvertToInt()-(int64_t)in.ConvertToInt())%(int64_t)Q+Q)%(int64_t)Q;
        if(e>(int64_t)Q/2)e-=Q; etrue[i]=(tsc>1)? (int64_t)llround((double)e/(double)tsc) : e;
    }
    // SW oracle, then ONE D query
    auto cT=cc->EvalFHEWtoCKKS(ct,slots,slots,pLWE,0,pLWE);
    Plaintext d; cc->Decrypt(keys.secretKey,cT,&d); d->SetLength(slots);
    auto o=d->GetRealPackedValue();

    // invert out = (p/2pi) sin(2pi*e/q)   ->   e = q/(2pi) * asin(out*2pi/p)
    uint32_t exact=0; double mx=0,ss=0;
    for(uint32_t i=0;i<slots;i++){
        double arg = o[i]*2.0*M_PI/(double)pLWE;
        if(arg>1) arg=1; if(arg<-1) arg=-1;
        double e_est = (double)Q/(2.0*M_PI)*std::asin(arg)/(double)tsc;
        double err = e_est-(double)etrue[i];
        ss+=err*err; mx=std::max(mx,std::fabs(err));
        if(llround(e_est)==etrue[i]) exact++;
        if(i<8) printf("  slot%02u e_true=%4lld  e_est=%9.4f  err=%+.4f\n",i,(long long)etrue[i],e_est,err);
    }
    for(uint32_t i=0;i<slots;i++){
        double arg=o[i]*2.0*M_PI/(double)pLWE; if(arg>1)arg=1; if(arg<-1)arg=-1;
        int64_t er=llround((double)Q/(2.0*M_PI)*std::asin(arg)/(double)tsc);
        int64_t bv=Borig[i];
        int64_t v=((bv-er)%(int64_t)Q+Q)%(int64_t)Q;
        const NativeVector&a=Aorig[i];
        csv<<bv; for(uint32_t kk=0;kk<n;kk++) csv<<","<<a[kk].ConvertToInt(); csv<<","<<er<<","<<v<<"\n";
    }
    tot_exact+=exact; tot+=slots; tot_ss+=ss; tot_mx=std::max(tot_mx,mx);
  }
    printf("\nscaleMod=%u slots=%u batches=%u tscale=%llu\n",scaleModSize,slots,batches,(unsigned long long)tsc);
    printf("DECRYPTION QUERIES USED: %u   equations: %u (need n=%u)\n",batches,tot,n);
    printf("exact e: %u/%u  RMS=%.4f  max=%.4f\n",tot_exact,tot,std::sqrt(tot_ss/tot),tot_mx);
    csv.close(); skf.close();
    cc->ClearStaticMapsAndVectors(); return 0;
}
