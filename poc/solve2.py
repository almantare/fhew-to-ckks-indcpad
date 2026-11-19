# Fast modular solve: pick n GF(2)-independent equations in ONE echelonization,
# then Hensel-lift the solution from mod 2 to mod 2^28.  Run: sage -python solve2.py
import time
from sage.all import Matrix, vector, GF, ZZ
t0=time.time()
LOGQ=28; q=1<<LOGQ
base=""
A_all=[]; v_all=[]
with open(base+"equations.csv") as f:
    for line in f:
        r=[int(x) for x in line.split(",")]
        A_all.append(r[1:-2]); v_all.append(r[-1])
strue=[int(x) for x in open(base+"secret.csv").read().strip().split(",")]
n=len(strue); M=len(A_all)
print("equations=%d n=%d  (load %.1fs)"%(M,n,time.time()-t0))

# one-shot pivot rows over GF(2)
Mf=Matrix(GF(2),[[x&1 for x in row] for row in A_all])
piv=Mf.pivot_rows()
print("rank over GF(2)=%d  pivot rows found=%d  (%.1fs)"%(len(piv),len(piv),time.time()-t0))
assert len(piv)==n, "need full column rank; collect more equations"
idx=list(piv)

# square integer system A x = v (mod q), A invertible mod 2 => unit det mod q
A=[[A_all[i][j] for j in range(n)] for i in idx]
v=[v_all[i] for i in idx]
# GF(2) inverse of A (reused each Hensel step)
A2=Matrix(GF(2),[[A[i][j]&1 for j in range(n)] for i in range(n)])
Ainv2=A2.inverse()
Ainv2Z=[[int(Ainv2[i][j]) for j in range(n)] for i in range(n)]  # 0/1
print("built GF(2) inverse  (%.1fs)"%(time.time()-t0))

# Hensel lift:  x s.t. A x = v (mod 2^28), starting mod 2
import array
x=[0]*n
Acols=A  # rows
for bit in range(LOGQ):
    # residual r = (v - A x) must be divisible by 2^bit; take (r>>bit) mod 2
    rbits=[0]*n
    for i in range(n):
        Ai=A[i]; acc=v[i]
        # acc = v_i - sum Ai[j]*x[j]
        s=0
        for j in range(n):
            xj=x[j]
            if xj: s+=Ai[j]*xj
        r=acc - s
        rbits[i]=(r>>bit)&1
    # dx = Ainv2 * rbits (mod 2)
    for j in range(n):
        Aij=Ainv2Z[j]; acc=0
        for i in range(n):
            if rbits[i]: acc^=Aij[i]
        if acc: x[j]+=(1<<bit)
    if bit%7==0: print("  hensel bit %d  (%.1fs)"%(bit,time.time()-t0))

def center(a):
    a%=q; return a-q if a>q//2 else a
srec=[center(v) for v in x]
match=sum(1 for a,b in zip(srec,strue) if a==b)
print("RECOVERED matches truth on %d/%d coords -> %s"%(match,n,"FULL KEY RECOVERY" if match==n else "PARTIAL"))
# consistency over all equations
bad=sum(1 for i in range(M) if (sum(A_all[i][j]*srec[j] for j in range(n))-v_all[i])%q!=0)
print("equations satisfied: %d/%d   total %.1fs"%(M-bad,M,time.time()-t0))
