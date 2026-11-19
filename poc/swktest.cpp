// DECISIVE TEST: is the FHEW->CKKS switching key simply a CKKS encryption of the LWE secret,
// retrievable via GetSwkFC() and readable with ONE decryption query?
// If yes, the ramp-probing attack is dominated by a trivial one-query break.
#include "openfhe.h"
#include "binfhecontext.h"
#include <iostream>
#include <vector>
#include <cmath>
using namespace lbcrypto;
int main(){
    uint32_t slots=64, scaleModSize=59, logQ=28, multDepth=13, ringDim=8192;
    CCParams<CryptoContextCKKSRNS> P; P.SetMultiplicativeDepth(multDepth);
    P.SetScalingModSize(scaleModSize); P.SetScalingTechnique(FIXEDAUTO);
    P.SetSecurityLevel(HEStd_NotSet); P.SetRingDim(ringDim); P.SetBatchSize(slots);
    auto cc=GenCryptoContext(P);
    cc->Enable(PKE);cc->Enable(KEYSWITCH);cc->Enable(LEVELEDSHE);cc->Enable(ADVANCEDSHE);cc->Enable(SCHEMESWITCH);
    auto keys=cc->KeyGen();
    auto ccLWE=std::make_shared<BinFHEContext>(); ccLWE->GenerateBinFHEContext(STD128,false,logQ,0,GINX,false);
    auto lwesk=ccLWE->KeyGen();
    uint32_t n=ccLWE->GetParams()->GetLWEParams()->Getn();
    cc->EvalFHEWtoCKKSSetup(ccLWE,slots,logQ); cc->SetBinCCForSchemeSwitch(ccLWE);
    cc->EvalFHEWtoCKKSKeyGen(keys,lwesk);

    // --- the entire "attack": fetch the public switching key and decrypt it once ---
    auto swk = cc->GetSwkFC();
    if(!swk){ std::cout << "GetSwkFC() returned null\n"; return 1; }
    Plaintext pt;
    cc->Decrypt(keys.secretKey, swk, &pt);
    pt->SetLength(n);
    auto rec = pt->GetRealPackedValue();

    // ground truth
    NativeInteger q = lwesk->GetModulus();
    double neg = q.ConvertToDouble()-1.0;
    auto& el = lwesk->GetElement();
    uint32_t match=0; double maxerr=0;
    for(uint32_t i=0;i<n;i++){
        double t = el[i].ConvertToDouble();
        double truth = (t==neg) ? -1.0 : t;
        double d = std::fabs(rec[i]-truth);
        maxerr = std::max(maxerr,d);
        if(llround(rec[i])==(long long)truth) match++;
    }
    printf("LWE dimension n = %u\n", n);
    printf("ONE decryption query on GetSwkFC():\n");
    printf("  coordinates recovered exactly : %u / %u\n", match, n);
    printf("  max |recovered - true|        : %.3e\n", maxerr);
    printf("  first 12 recovered / true     : ");
    for(uint32_t i=0;i<12;i++){ double t=el[i].ConvertToDouble(); printf("%+.0f/%+.0f ", rec[i], (t==neg)?-1.0:t); }
    printf("\n%s\n", match==n ? "=> FULL KEY RECOVERY IN ONE QUERY" : "=> not fully recovered");
    cc->ClearStaticMapsAndVectors(); return 0;
}
