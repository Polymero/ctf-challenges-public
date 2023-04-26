import time
ALP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_{}!?"

message = "zptLKTGlJ2r{6nZlMvaMj8AT1zAzlsGqdORn6JVc14JmB?RnT5IXB6Ce?bJ{B8}ty_nHL{k{wR?bCMTqLnnqA_It}7a8XX3QwBFExeZ3}Y?w1!3LHVcVXQS_OS}crc01cuwFG{czY!FRgarAl{9NhcS3Xsoye7AH!B3q{Seeh578R!h4x7?62pE9TA9x8{oGgdX0Uv_W9wJO9Sh9zPbGog3zYwolBL2zOxzoXrf4ZJ0PF{HUYA{kGkL05W2zZKWny3H?y8i85X8Ib_L08csX5V73s77ptrMEYWI5JSa6Crb!qj!eoZK}CLQyRmNBMCSd2IOwy_zYIBN{h22LEVjSvdS5CU!bA!2LvBxWLpO!_!zmbhCXEadPVmIRVqPsZ!EwuFUZH_oKg5TgRm{A4EhT{e7IJn3H1cZ_Zsu}"
hierocipher = "QpFKc9fZ1e0LKFbHjDgMf8CDO7?2p0b5XqZxyFUQ6TRYOc3g8w9Ph7nQCCe3asZXeqoDW9QZXWkAR}qgWXiEVH?d{gurMH1meQ6XPwLi7L!pARz1mJ2wVg5irFxWj{op5tLOI_CN0o857S3dpKi9dJGAu47heF23VBXmRHtEKxk5c_h3WKL33Rklcaxa14!Bf3e8iXW8TX0S7flhmvm0o9gGEZvPP!dp4GNVeuf0k1?rX7nW?2VZWmocQNf}mWGpQisETDyLEK1uYM1NqqW2YqfBOFI2gQK9Mr5uBUlCx2HzB8N!N{3GH{vLZ0S5Jo}17k8yidBibec}OfgSkHXbKQWZaMIU}6XvmDj_TbbdAMP15}YmwwAwZA64P6fHJ1PRSlFBtoTzNFMhe6TiPCwAonDWp_c8l8J}Ay3Y"

t0 = time.time()

Z = GF(67)
msgvec = Matrix(Z, [ALP.index(i) for i in message]).T
cipvec = Matrix(Z, [ALP.index(i) for i in hierocipher]).T

keysizes = [1,2,3,4,5]

parspace = sum([i**2 for i in keysizes])
P = PolynomialRing(Z, parspace, names=['k'+str(i) for i in range(parspace)])

coefs = list(P.gens())
SymKs = { i : Matrix(P, i, i, [coefs.pop(0) for _ in range(i*i)]) for i in keysizes }

SymCK = identity_matrix(prod(keysizes))
for i in keysizes:
    SymCK = block_diagonal_matrix([SymKs[i] for _ in range(prod(keysizes)//i)]) * SymCK
    
assert SymCK[:60,60:] == zero_matrix(60)
assert SymCK[60:,:60] == zero_matrix(60)
assert SymCK[:60,:60] == SymCK[60:,60:]

resize = [3,4,5]

SymCK = SymCK.subs(k0=ALP.index('f'),
                   k1=ALP.index('l'),
                   k2=ALP.index('a'),
                   k3=ALP.index('g'),
                   k4=ALP.index('{'),
                   k53=ALP.index('}'))[:prod(resize),:prod(resize)]

msgmat = Matrix(Z, msgvec.nrows()//prod(resize), prod(resize), msgvec.list()).T
cipmat = Matrix(Z, msgvec.nrows()//prod(resize), prod(resize), cipvec.list()).T

PolyEqs = (SymCK * msgmat - cipmat).list()

t1 = time.time()
print('Polynomial Equations: {:.2f} sec'.format(t1 - t0))

GB = P.ideal([i for i in PolyEqs]).groebner_basis()

t2 = time.time()
print('Gröbner basis: {:.2f} sec'.format(t2 - t1))

print('\n3x3 key:')
for k in range(67):
    res = ''.join([ALP[-i.subs(k13=k).monomial_coefficient(P(1))] for i in GB])[1:9] + ALP[k]
    if ('{' not in res) and ('}' not in res) and ('_' in res):
        print(k,res)
    
print('\n4x4 key:')
for k in range(67):
    res = ''.join([ALP[-i.subs(k29=k).monomial_coefficient(P(1))] for i in GB])[9:24] + ALP[k]
    if ('{' not in res) and ('}' not in res) and ('_' in res):
        print(k,res)
    
print('\n5x5 key:')
for k in range(67):
    res = ''.join([ALP[-i.monomial_coefficient(P(1))*k] for i in GB])[24:]
    if res[-1] == '}':
        print(k,res)

# Polynomial Equations: 8.90 sec
# Gröbner basis: 1.29 sec
#
# 3x3 key:
# 9 5c_bisjcJ
# 38 _OfvRWzOm
# 44 h3y!_d03s
#
# 4x4 key:
# 3 DCH_2DSJJgDS_giD
# 10 KdBcuK8ee_K8c_YK
# 17 R4_9mRjzzZRj9ZOR
# 26 a_Qu?aWLL2aWu2xa
# 55 37nU03_ffG3_UG!3
# 62 _Th1s_l00k_l1k3_
#
# 5x5 key:
# 45 4_PYr4m1d_SCh3m3_t0_y0u}

# flag{h3y!_d03s_Th1s_l00k_l1k3_4_PYr4m1d_SCh3m3_t0_y0u}