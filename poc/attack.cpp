// Full reverse-direction attack, with optional decryption-noise flooding (argv[3], phase std)
// and amplification (argv[4], t).  Recovers the FHEW/LWE secret via the FHEW->CKKS oracle.
//   e-recovery: scale ct by t, homomorphically shift b over a grid, one packed EvalFHEWtoCKKS
//   call -> phase ramp (flooding injected at decrypt), line fit -> e = (crossing-delta)/t.
//   Equations use the ORIGINAL (a,b):  v = (b - e) mod q = <a,s>.  n eqs -> modular solve.
#include "openfhe.h"
#include "binfhecontext.h"
#include <iostream>
#include <vector>
#include <fstream>
#include <cmath>
#include <random>
using namespace lbcrypto;

int main(int argc,char**argv){
    uint32_t G   =(argc>1)?std::atoi(argv[1]):4;
    uint32_t Mct =(argc>2)?std::atoi(argv[2]):1400;
    double flood =(argc>3)?std::atof(argv[3]):0.0;        // flooding std, phase units
    uint64_t tsc =(argc>4)?std::strtoull(argv[4],0,10):1; // amplification factor t
    uint32_t pLWE=256, slots=512, scaleModSize=(argc>5)?(uint32_t)std::atoi(argv[5]):59, logQ=28, multDepth=13, ringDim=8192, W=slots/G;

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
    std::mt19937_64 rng(999); std::normal_distribution<double> gauss(0,1); double flood_msg=flood/(double)Delta;
    printf("n=%u Delta=%lld scaleMod=%u pack=%u eqs=%u flood=%.1f tscale=%llu\n",
           n,(long long)Delta,scaleModSize,G,Mct,flood,(unsigned long long)tsc);

    std::vector<int64_t> cg(W);
    for(uint32_t i=0;i<W;i++) cg[i]=Delta/4+(int64_t)(((__int128)(Delta/2)*i)/(W-1));
    auto fit=[&](const std::vector<double>&o,uint32_t off)->double{
        double Sx=0,Sy=0,Sxx=0,Sxy=0;int N=0;
        for(uint32_t i=0;i<W;i++){double y=o[off+i]; if(y<0.25||y>0.75)continue;
            double x=(double)(cg[i]-Delta/2);Sx+=x;Sy+=y;Sxx+=x*x;Sxy+=x*y;N++;}
        if(N<3)return 1e18; double b=(N*Sxy-Sx*Sy)/(N*Sxx-Sx*Sx),a=(Sy-b*Sx)/N; return -(0.5-a)/b;
    };
    // probe scaled ciphertexts (As,Bs already *t mod q); returns raw crossing value (= t*e + delta)
    auto probe=[&](std::vector<NativeVector>&As,std::vector<NativeInteger>&Bs,uint32_t g,std::vector<double>&raw){
        std::vector<LWECiphertext> pr(slots);
        for(uint32_t gg=0;gg<g;gg++)for(uint32_t i=0;i<W;i++){uint64_t c=(uint64_t)((cg[i]%(int64_t)Q+Q)%Q);
            pr[gg*W+i]=std::make_shared<LWECiphertextImpl>(As[gg],Bs[gg].ModAddFast(NativeInteger(c),q),NativeInteger(pLWE));}
        for(uint32_t i=g*W;i<slots;i++) pr[i]=pr[0];
        auto cT=cc->EvalFHEWtoCKKS(pr,slots,slots,pLWE,0,pLWE);
        Plaintext d; cc->Decrypt(keys.secretKey,cT,&d); d->SetLength(slots);
        std::vector<double> o=d->GetRealPackedValue();
        if(flood>0) for(auto&x:o) x+=flood_msg*gauss(rng);
        raw.assign(g,0); for(uint32_t gg=0;gg<g;gg++) raw[gg]=fit(o,gg*W);
    };
    auto scale=[&](const NativeVector&a,NativeInteger b,NativeVector&as,NativeInteger&bs){
        as=a; for(uint32_t i=0;i<n;i++) as[i]=a[i].ModMul(NativeInteger(tsc),q); bs=b.ModMul(NativeInteger(tsc),q);
    };
    // calibration a=0,b=0 (scaling/flooding same): delta = raw at e=0
    std::vector<NativeVector> Az(1,NativeVector(n,q)); for(uint32_t i=0;i<n;i++)Az[0][i]=0;
    std::vector<NativeInteger> Bz(1,NativeInteger(0)); std::vector<double> cr; probe(Az,Bz,1,cr); double delta=cr[0];
    printf("calibration delta=%.4f\n",delta);

    std::ofstream csv("equations.csv");
    std::ofstream skf("secret.csv");
    for(uint32_t k=0;k<n;k++){int64_t sv=s[k].ConvertToInt(); if(sv>(int64_t)Q/2)sv-=Q; skf<<sv<<(k+1<n?",":"\n");}

    uint32_t done=0,exact=0; double mx=0;
    while(done<Mct){ uint32_t g=std::min(G,Mct-done);
        std::vector<NativeVector> Ao(g),As(g); std::vector<NativeInteger> Bo(g),Bs(g);
        std::vector<int64_t> et(g),bv(g);
        for(uint32_t gg=0;gg<g;gg++){ auto ct=ccLWE->Encrypt(lwesk,0,LARGE_DIM,pLWE,q);
            Ao[gg]=ct->GetA(); Bo[gg]=ct->GetB(); bv[gg]=Bo[gg].ConvertToInt();
            NativeInteger in(0); for(uint32_t i=0;i<n;i++) in+=Ao[gg][i].ModMulFast(s[i],q,mu); in.ModEq(q);
            int64_t e=((bv[gg]-(int64_t)in.ConvertToInt())%(int64_t)Q+Q)%(int64_t)Q; if(e>(int64_t)Q/2)e-=Q; et[gg]=e;
            scale(Ao[gg],Bo[gg],As[gg],Bs[gg]); }
        std::vector<double> raw; probe(As,Bs,g,raw);
        for(uint32_t gg=0;gg<g;gg++){ double e_est=(raw[gg]-delta)/(double)tsc; int64_t er=llround(e_est);
            mx=std::max(mx,std::fabs(e_est-et[gg])); if(er==et[gg]) exact++;
            int64_t v=((bv[gg]-er)%(int64_t)Q+Q)%(int64_t)Q;
            csv<<bv[gg]; for(uint32_t kk=0;kk<n;kk++) csv<<","<<Ao[gg][kk].ConvertToInt(); csv<<","<<er<<","<<v<<"\n"; }
        done+=g;
    }
    printf("DONE: %u eqs, exact e %u/%u (%.1f%%), max|e_err|=%.3f\n",Mct,exact,Mct,100.0*exact/Mct,mx);
    cc->ClearStaticMapsAndVectors(); return 0;
}
