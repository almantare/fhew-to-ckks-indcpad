// Diagnostics: (1) a=0 noiseless calibration of the crossing offset delta;
// (2) repeatability of e_est for a fixed ciphertext (is transform noise deterministic?);
// (3) effect of scaleModSize on per-ciphertext scatter.
#include "openfhe.h"
#include "binfhecontext.h"
#include <iostream>
#include <vector>
#include <cmath>
using namespace lbcrypto;

static double fit_ehat(const std::vector<double>&o,const std::vector<int64_t>&cg,int64_t Delta){
    double Sx=0,Sy=0,Sxx=0,Sxy=0; int N=0;
    for(size_t i=0;i<o.size();++i){ if(o[i]<0.25||o[i]>0.75)continue;
        double x=(double)(cg[i]-Delta/2),y=o[i]; Sx+=x;Sy+=y;Sxx+=x*x;Sxy+=x*y;N++; }
    double beta=(N*Sxy-Sx*Sy)/(N*Sxx-Sx*Sx), alpha=(Sy-beta*Sx)/N;
    return -(0.5-alpha)/beta;  // e_est such that phase=Delta/2 at o=0.5
}

int main(int argc,char**argv){
    uint32_t pLWE=256, slots=512, scaleModSize=(argc>1)?std::atoi(argv[1]):50, logQ=28;
    uint32_t multDepth=3+9+1, ringDim=8192;
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
    std::cout<<"scaleModSize="<<scaleModSize<<" n="<<n<<" Delta="<<Delta<<"\n";

    std::vector<int64_t> cg(slots);
    auto build=[&](int64_t phase_center){ for(uint32_t i=0;i<slots;i++) cg[i]=Delta/4+(int64_t)(((__int128)(Delta/2)*i)/(slots-1)); };
    build(0);

    auto query=[&](const NativeVector&a, NativeInteger b0)->double{
        std::vector<LWECiphertext> pr(slots);
        for(uint32_t i=0;i<slots;i++){ uint64_t c=(uint64_t)((cg[i]%(int64_t)Q+Q)%Q);
            pr[i]=std::make_shared<LWECiphertextImpl>(a,b0.ModAddFast(NativeInteger(c),q),NativeInteger(pLWE)); }
        auto cT=cc->EvalFHEWtoCKKS(pr,slots,slots,pLWE,0,pLWE);
        Plaintext d; cc->Decrypt(keys.secretKey,cT,&d); d->SetLength(slots);
        auto o=d->GetRealPackedValue(); return fit_ehat(o,cg,Delta);
    };

    // (1) a=0 calibration: phase = b known exactly. Use b=0 -> true phase-at-c is c, crossing at c=Delta/2 -> e_true_equiv=0
    NativeVector zero(n,q); for(uint32_t i=0;i<n;i++) zero[i]=0;
    double delta = query(zero, NativeInteger(0));   // e_est for known-zero phase == the offset delta
    std::cout<<"(1) a=0 calibration: delta (offset) = "<<delta<<"\n";

    // (2) repeatability on one real ciphertext
    auto ct=ccLWE->Encrypt(lwesk,0,LARGE_DIM,pLWE,q);
    const NativeVector&a=ct->GetA(); NativeInteger inr(0);
    for(uint32_t i=0;i<n;i++) inr+=a[i].ModMulFast(s[i],q,mu); inr.ModEq(q);
    int64_t et=(((int64_t)ct->GetB().ConvertToInt()-(int64_t)inr.ConvertToInt())%(int64_t)Q+Q)%(int64_t)Q; if(et>(int64_t)Q/2)et-=Q;
    double r1=query(a,ct->GetB())-delta, r2=query(a,ct->GetB())-delta;
    std::cout<<"(2) fixed ct e_true="<<et<<"  run1="<<r1<<" run2="<<r2<<" (repeatable if equal)\n";

    // (3) scatter over 8 ciphertexts after calibration
    double ss=0,mx=0; int nn=8;
    for(int j=0;j<nn;j++){
        auto c2=ccLWE->Encrypt(lwesk,0,LARGE_DIM,pLWE,q); const NativeVector&aa=c2->GetA();
        NativeInteger in2(0); for(uint32_t i=0;i<n;i++) in2+=aa[i].ModMulFast(s[i],q,mu); in2.ModEq(q);
        int64_t e2=(((int64_t)c2->GetB().ConvertToInt()-(int64_t)in2.ConvertToInt())%(int64_t)Q+Q)%(int64_t)Q; if(e2>(int64_t)Q/2)e2-=Q;
        double est=query(aa,c2->GetB())-delta; double err=est-e2; ss+=err*err; mx=std::max(mx,std::fabs(err));
        printf("   ct%d e_true=%4lld e_est=%8.3f err=%+.3f\n",j,(long long)e2,est,err);
    }
    printf("(3) after calibration: RMS=%.3f max=%.3f\n",std::sqrt(ss/nn),mx);
    cc->ClearStaticMapsAndVectors(); return 0;
}
