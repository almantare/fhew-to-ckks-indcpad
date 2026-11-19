// Calibration: does OpenFHE FHEW->CKKS act as an exact LWE decryption oracle?
// We take a fresh LWE encryption of 0, homomorphically shift b by a constant c,
// scheme-switch to CKKS, decrypt, and watch the output as a function of c.
// Prediction: output ~ round((e + c)/Delta), a step that flips at c = Delta/2 - e.
// If so, the flip location leaks e (hence <a,s>), independent of CKKS noise flooding.
#include "openfhe.h"
#include "binfhecontext.h"
#include <iostream>
#include <vector>
using namespace lbcrypto;

int main(int argc, char** argv) {
    uint32_t pLWE       = (argc > 1) ? std::atoi(argv[1]) : 256;
    uint32_t logQ_ccLWE = 28;

    ScalingTechnique scTech = FIXEDAUTO;
    uint32_t multDepth = 3 + 9 + 1;
    uint32_t scaleModSize = 50, ringDim = 8192;
    uint32_t slots = 128;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(scTech);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(slots);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE); cc->Enable(KEYSWITCH); cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE); cc->Enable(SCHEMESWITCH);
    auto keys = cc->KeyGen();

    auto ccLWE = std::make_shared<BinFHEContext>();
    ccLWE->GenerateBinFHEContext(STD128, false, logQ_ccLWE, 0, GINX, false);
    auto lwesk = ccLWE->KeyGen();
    uint32_t n = ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << "LWE n=" << n << " pLWE=" << pLWE << " logQ=" << logQ_ccLWE << std::endl;

    cc->EvalFHEWtoCKKSSetup(ccLWE, slots, logQ_ccLWE);
    cc->SetBinCCForSchemeSwitch(ccLWE);
    cc->EvalFHEWtoCKKSKeyGen(keys, lwesk);

    uint64_t Q = 1ULL << logQ_ccLWE;
    NativeInteger q(Q);
    uint64_t Delta = Q / pLWE;
    std::cout << "Q=" << Q << " Delta=" << Delta << " boundary Delta/2=" << Delta/2 << std::endl;

    // Fresh encryption of 0
    auto ct = ccLWE->Encrypt(lwesk, 0, LARGE_DIM, pLWE, q);

    // Ground-truth phase e = (b - <a,s>) mod q, centered  (validation only)
    NativeVector s = lwesk->GetElement(); s.SwitchModulus(q);
    NativeInteger mu = q.ComputeMu();
    NativeInteger inner(0);
    const NativeVector& a = ct->GetA();
    for (uint32_t i = 0; i < n; ++i) inner += a[i].ModMulFast(s[i], q, mu);
    inner.ModEq(q);
    int64_t bval = ct->GetB().ConvertToInt();
    int64_t innerv = inner.ConvertToInt();
    int64_t e_true = ((bval - innerv) % (int64_t)Q + Q) % Q;
    if (e_true > (int64_t)Q/2) e_true -= Q;
    std::cout << "GROUND TRUTH e_true = " << e_true << "  (b=" << bval << ")" << std::endl;

    // Fine sweep of c centered at Delta/2, radius R, one packed EvalFHEWtoCKKS call
    int64_t R = 60;
    std::vector<LWECiphertext> probes(slots);
    std::vector<int64_t> cvals(slots);
    for (uint32_t i = 0; i < slots; ++i) {
        int64_t c = (int64_t)Delta/2 - R + (int64_t)((2*R) * i / (slots-1));
        cvals[i] = c;
        NativeInteger newb = ct->GetB().ModAddFast(NativeInteger((uint64_t)((c % (int64_t)Q + Q) % Q)), q);
        probes[i] = std::make_shared<LWECiphertextImpl>(a, newb, NativeInteger(pLWE));
    }
    auto cText = cc->EvalFHEWtoCKKS(probes, slots, slots, pLWE, 0, pLWE);
    Plaintext dec; cc->Decrypt(keys.secretKey, cText, &dec);
    dec->SetLength(slots);
    auto out = dec->GetRealPackedValue();

    std::cout << "\n  c-Delta/2   output    (flip => e = Delta/2 - c*)\n";
    for (uint32_t i = 0; i < slots; ++i) {
        int64_t off = cvals[i] - (int64_t)Delta/2;
        printf("  %+6lld    %10.5f\n", (long long)off, out[i]);
    }
    // Locate flip (output crosses 0.5)
    int64_t cstar = 0; bool found=false;
    for (uint32_t i = 1; i < slots; ++i) {
        if (out[i-1] < 0.5 && out[i] >= 0.5) {
            double t = (0.5 - out[i-1]) / (out[i]-out[i-1]);
            cstar = (int64_t)llround(cvals[i-1] + t*(cvals[i]-cvals[i-1]));
            found=true; break;
        }
    }
    if (found) {
        int64_t e_rec = (int64_t)Delta/2 - cstar;
        std::cout << "\nRECOVERED e = Delta/2 - c* = " << e_rec
                  << "   (true " << e_true << ", err " << (e_rec - e_true) << ")\n";
    } else std::cout << "\nNo clean flip found in window; widen R.\n";

    cc->ClearStaticMapsAndVectors();
    return 0;
}
