#!/usr/bin/env python3
# LUCKY_HUB_PY_LAUNCHER_V2
import base64 as _b, hashlib as _h, hmac as _m, struct as _s
_P=(
    'OjScmSx8kvP+0+wKM+2i-i~Hq?Ea%!_AvYTtabCM0$d?hIz@{TfHwozq=2N)X=2zjaZ86T-@t+K;*Ln;Z0eWgv92'
    'j(v%cIZmwWtKQb%HR3wU7Y=Vm@UpnlH*o?K8nnRZ4k-^q6ORSu|og+=QqGPbc9Yw)LT*iOF!!@^im>?xp}?;liom'
    '3F{F8M`?SZ#03rX<27oW_cejj>BGM*#@J^M9S8x)4bt(Q&q_D<z8A@qRQKz6Palfq}&5@MI`ptz_{+!M_`pgFmP-'
    'U|D;ZgH_&{1%Onu1?!Mpq!I~)^U4>7NQ!R9@?>whwhj@eh+gTnTPa}rVzQjy9<*UOt%E5ol1VD3q<#~sh#M-g>@u'
    'E^sfh__9`EVi;yz*DnwvnlO@2YKjo-b2dKyDy~b3O288;e1k1ST5zY7eiOS4K#uQ4^6ltP6-y`z*Splz!1c0<?Gz'
    'h(p~(>T4DAst>0sppP#<pw%q(sH+G-WA>m6){_gO`+hCMpwe2+rLpPMLVDl?>?i&sRLBt3Oy|8-K_wlUp}XrCjBD'
    '^<wKmlom+y<T>&tMB`Bk;#A+=TI40uf)_JCU_R0KIC3A^s};9m}V;}Unuelui5=1nblCNY%_=Ytger>dK)=WVZG6'
    'R`om=bIz4vv?NT1I_h@@AGvG2IPYxJ6)r*(ht`@Jh>8@np|pgZL`B6*EH8y)KPvm)Vd0qT8Pa;k*m`D*K9KG@#48'
    'CJNu1#4veUDB2r>Y_Otd!mSE~|nR_0$Pz%i6&{{hGrxjYYM~fE^yy%)4f8qMg-XUALNs2+XLodagj11vnQi^^OiZ'
    'BKR?YhoVLK)7|j_ZCW-eq#@UXbOcEVO@Ib$n`LV+iZBuRLdq29FHK<0|%$XW6huKZrjj%;CvKC8>;hF*|_?`T7b9'
    '3M2ajA?H_~fXf96-fCYyiBI?i)UehAHfWvVy?U;Fpy+<XCmhCR908*<X6#f6bKr95eUKxIdU3n)brTMjI22aN<2#'
    '|vv2D_%`)*(3zKyAI)0heewRp<z-F+z?a?g)wc<-vzVN~$_`I-_1^j4e9Li*qyTecduaAY;=1NMM8#XCzJ`(NXN6'
    '}R2OvVc=(F<{iSsCd^&2uZT=i<NDr(?B$1J0@gNg(XtY?`2O>uL-7JY{;P9ca>0XQOtEQ)u)gE40khd_`f*{MDy('
    'lL_mN4_N(P}NeJ!-8~n|Vp$nU1?P~hCl)P9k<U{G*-0=Q`Sj}{IjEgI<!7kftTsv-JCQLPGQeKqtYHqIhu5k`Z@K'
    '$H!SF>(cnmXaAgC7Gy9omX72);m|F-&Kr1OIS@u#30Yd9-z&&Ol4ABA+PwlI9Rc!{`p@`e^c27%!=ofMjIDsAa3b'
    'cx+BIDpHwHTxcmpU}(u%Z{KE=&v}kpk4SYL2Sj{8e$N`ds5x0IjS;4;u<VCKfuJ`5e8gFD6t8t$^vw;qaqCw21E9'
    '1fNY<ky@FwxNH_mjbvI7&<DpEcx;JF-lJrFs>?LH&MasZ(roWQF!>)14?_`#GfEyQZ)CP}$VRdx4no%Oru&oKPgv'
    '%OP^drWz4?CXyh9rK?h1PfVouU=`~4|@*(de?(#OU5tWxI2gLL&L5^3i{66enZJVdBoiGQJ-<uaORY1ZYGx?Kn}m'
    'dv*Uy5YH>=^uR?hIK`}d9=xAN>&$tSv*vdLg-}^~y`7?Em|G-c=2v*VVw>$0jW}$g*2i1+8rf>4!Xx4cW7=<L-6v'
    'k5Fpt>iTy?{utJ-u_UBRD^PTA}X-<qFfiwVz;iZ#~~XuqG&52l&o-YN5c*?98d_o}>3VrT{(>jZ>qt4dk0Bi`1<u'
    'RI<dUaTwN#GA)5j+S}%<8rpJ8m5LIu?;6I5M+CZIg+d_{%228*Eh@&<?BMh(nhLQGK8Y`N*ZDD%1L}_p9Tw6?A^?'
    'Zg@%}d'
)
_E=bytes.fromhex('4ec2eadf7d6b81679a931eb14ab062ac1ac35fe3fb7d4079f758e9b3d5002165')
_M=bytes.fromhex('1646ce30a2ec37e3f472eb11d11f98fb0b371ac2e8377ac2f09592cc21ff14e0')
_B=_b.b85decode(''.join(_P).encode('ascii'))
_H=len(b'LUCKYHUBPY\x01')+32
_BODY,_TAG=_B[:-32],_B[-32:]
if not _m.compare_digest(_TAG,_m.new(_M,_BODY,_h.sha256).digest()): raise SystemExit('Protected file damaged')
_nonce=_B[len(b'LUCKYHUBPY\x01')+16:_H]
_C=_B[_H:-32]; _O=bytearray(); _i=0
while len(_O)<len(_C):
 _O.extend(_m.new(_E,b'LUCKY-HUB-PY-STREAM-v1'+_nonce+_s.pack('>Q',_i),_h.sha256).digest()); _i+=1
exec(compile(bytes(a^b for a,b in zip(_C,_O)),__file__,'exec'),globals(),globals())
