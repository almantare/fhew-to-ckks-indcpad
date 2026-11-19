// How much decryption noise flooding is needed to defeat the LWE-error leak?
// We inject Gaussian flooding of std = flood_phase/Delta (message units) into each decrypted
// slot (fresh per repeat), average over `reps` repeats (attacker re-queries), line-fit, round.
// Report exact-e rate over K ciphertexts.  Sweep flood_phase to map the countermeasure.
#include "openfhe.h"
#include "binfhecontext.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <random>
using namespace lbcrypto;

int main(int argc,char**argv){
    double flood_phase=(argc>1)?std::atof(argv[1]):0.0; // std of injected noise, in PHASE units
    uint32_t reps=(argc>2)?std::atoi(argv[2]):1;         // attacker averages this many fresh-flood queries
    uint32_t K=(argc>3)?std::atoi(argv[3]):40;           // ciphertexts tested
    uint64_t tscale=(argc>4)?std::strtoull(argv[4],0,10):1; // amplify LWE ct by this factor before switching
    uint32_t tagmode=(argc>6)?(uint32_t)std::atoi(argv[6]):0; // 1 = flooding calibrated to noise tag (sigma ∝ t)
    uint32_t pLWE=256, slots=512, scaleModSize=(argc>5)?(uint32_t)std::atoi(argv[5]):59, logQ=28, multDepth=13, ringDim=8192, W=128, G=4;

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
    std::mt19937_64 rng(12345); std::normal_distribution<double> gauss(0.0,1.0);
    double flood_eff = tagmode ? flood_phase*(double)tscale : flood_phase; // tag-calibrated grows with t
    double flood_msg = flood_eff/(double)Delta;

    std::vector<int64_t> cg(W);
    for(uint32_t i=0;i<W;i++) cg[i]=Delta/4+(int64_t)(((__int128)(Delta/2)*i)/(W-1));
    auto fit=[&](const std::vector<double>&o,uint32_t off)->double{
        double Sx=0,Sy=0,Sxx=0,Sxy=0; int N=0;
        for(uint32_t i=0;i<W;i++){ double y=o[off+i]; if(y<0.25||y>0.75)continue;
            double x=(double)(cg[i]-Delta/2); Sx+=x;Sy+=y;Sxx+=x*x;Sxy+=x*y;N++; }
        if(N<3)return 1e18; double b=(N*Sxy-Sx*Sy)/(N*Sxx-Sx*Sx),a=(Sy-b*Sx)/N; return -(0.5-a)/b;
    };
    // build a G-packed probe query for G ciphertexts, return per-ct e_est (averaged over reps)
    auto batch=[&](std::vector<NativeVector>&A,std::vector<NativeInteger>&B,uint32_t g,std::vector<double>&est){
        std::vector<LWECiphertext> pr(slots);
        for(uint32_t gg=0;gg<g;gg++)for(uint32_t i=0;i<W;i++){ uint64_t c=(uint64_t)((cg[i]%(int64_t)Q+Q)%Q);
            pr[gg*W+i]=std::make_shared<LWECiphertextImpl>(A[gg],B[gg].ModAddFast(NativeInteger(c),q),NativeInteger(pLWE)); }
        for(uint32_t i=g*W;i<slots;i++) pr[i]=pr[0];
        auto cT=cc->EvalFHEWtoCKKS(pr,slots,slots,pLWE,0,pLWE);
        Plaintext d; cc->Decrypt(keys.secretKey,cT,&d); d->SetLength(slots);
        auto base=d->GetRealPackedValue();
        est.assign(g,0);
        for(uint32_t gg=0;gg<g;gg++){
            double acc=0;
            for(uint32_t r=0;r<reps;r++){ std::vector<double> o(base);
                for(uint32_t i=0;i<W;i++) o[gg*W+i]+=flood_msg*gauss(rng);
                acc+=fit(o,gg*W); }
            est[gg]=acc/reps;
        }
    };
    // calibration (a=0,b=0), also flooded+averaged the same way
    std::vector<NativeVector> Az(1,NativeVector(n,q)); for(uint32_t i=0;i<n;i++)Az[0][i]=0;
    std::vector<NativeInteger> Bz(1,NativeInteger(0)); std::vector<double> ce; batch(Az,Bz,1,ce); double delta=ce[0];

    uint32_t exact=0; double mx=0,ss=0;
    uint32_t done=0;
    while(done<K){ uint32_t g=std::min(G,K-done);
        std::vector<NativeVector> A(g); std::vector<NativeInteger> B(g); std::vector<int64_t> et(g),bv(g);
        for(uint32_t gg=0;gg<g;gg++){ auto ct=ccLWE->Encrypt(lwesk,0,LARGE_DIM,pLWE,q);
            NativeVector a0=ct->GetA(); NativeInteger b0=ct->GetB();
            NativeInteger in(0); for(uint32_t i=0;i<n;i++) in+=a0[i].ModMulFast(s[i],q,mu); in.ModEq(q);
            int64_t e=(((int64_t)b0.ConvertToInt()-(int64_t)in.ConvertToInt())%(int64_t)Q+Q)%(int64_t)Q; if(e>(int64_t)Q/2)e-=Q; et[gg]=e;
            // amplify: (a,b) -> t*(a,b) mod q  (phase -> t*phase = t*e for zero message)
            NativeVector at(a0); for(uint32_t i=0;i<n;i++) at[i]=a0[i].ModMul(NativeInteger(tscale),q);
            A[gg]=at; B[gg]=b0.ModMul(NativeInteger(tscale),q); bv[gg]=B[gg].ConvertToInt(); }
        std::vector<double> est; batch(A,B,g,est);
        for(uint32_t gg=0;gg<g;gg++){ double e_est=(est[gg]-delta)/(double)tscale;
            double d=e_est-et[gg]; ss+=d*d; mx=std::max(mx,std::fabs(d));
            if(llround(e_est)==et[gg]) exact++; }
        done+=g;
    }
    printf("scaleMod=%u tscale=%llu flood=%.1f tag=%u eff=%.0f reps=%u : exact_e=%u/%u  RMS=%.3f  max=%.3f\n", scaleModSize,(unsigned long long)tscale,flood_phase,tagmode,flood_eff,reps,exact,K,std::sqrt(ss/K),mx);
    cc->ClearStaticMapsAndVectors(); return 0;
}
