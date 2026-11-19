# Solve  A s = v  (mod q=2^28)  for the ternary LWE secret, from the leaked equations.
# Power-of-two modulus: select n rows independent over GF(2) (=> unit det mod 2^28), invert, multiply.
# Run:  sage -python solve.py
import csv
from sage.all import Matrix, vector, GF, Zmod, ZZ

LOGQ=28; q=1<<LOGQ
base=""
rows=[]
with open(base+"equations.csv") as f:
    for line in f:
        rows.append([int(x) for x in line.strip().split(",")])
strue=[int(x) for x in open(base+"secret.csv").read().strip().split(",")]
n=len(strue)
# columns: b, a0..a_{n-1}, e_est, v
A_all=[r[1:1+n] for r in rows]
v_all=[r[-1] for r in rows]
print("equations=%d  n=%d"%(len(rows),n))

# pick n rows independent over GF(2)
F=GF(2)
Msel=Matrix(F, 0, n)
idx=[]
for i,row in enumerate(A_all):
    cand=Matrix(F,[[x&1 for x in row]])
    test=Msel.stack(cand)
    if test.rank()==Msel.nrows()+1:
        Msel=test; idx.append(i)
        if len(idx)==n: break
print("selected %d independent rows (need %d)"%(len(idx),n))
assert len(idx)==n, "not enough independent rows; collect more"

R=Zmod(q)
An=Matrix(R,[A_all[i] for i in idx])
vn=vector(R,[v_all[i] for i in idx])
srec=An.solve_right(vn)
# center to {-1,0,1}
def center(x):
    x=int(x)%q
    return x-q if x>q//2 else x
srec_c=[center(x) for x in srec]
match=sum(1 for a,b in zip(srec_c,strue) if a==b)
print("RECOVERED secret matches truth on %d / %d coordinates"%(match,n))
print("FULL KEY RECOVERY" if match==n else "PARTIAL (%d wrong)"%(n-match))
# also verify against ALL equations (consistency)
bad=0
for i in range(len(rows)):
    lhs=sum(A_all[i][j]*srec_c[j] for j in range(n))%q
    if lhs!=(v_all[i]%q): bad+=1
print("equations satisfied by recovered s: %d / %d"%(len(rows)-bad,len(rows)))
