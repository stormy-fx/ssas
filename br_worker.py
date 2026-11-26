#!/usr/bin/env python3
# LUCKY_HUB_PY_LAUNCHER_V2
import base64 as _b, hashlib as _h, hmac as _m, struct as _s
_P=(
    'OjScmSx8kvP+0*RsKto}iVtH}o+>n+YXyTLH`&>k2n{0*D>21VZrAWehz2)RRsu^usAg|<W=f+8upASLrX(3h#2Z'
    'ggc5zT20$7!pr3)efQ*JbR7sPap!41Z;YmoB{ijoGCEhK?EsBbu=uZD#srbv6&Q|=5tt?PwSt)oojE}<sK@$Kj6#'
    'IBY?5XXux?a+XliVZ4$d^KbM3eOMLOanX{ExNO$1*~oEV;Lb%q$L6a%OtGS3`0uiQ}VEr#!KkwjM+Z>Ps9QvF44+'
    '|O4X~d-5?lmNaTY;k}?GNR&YH^+kZg;P?anQOv5TCILmnPi|x(vQPXH8>4IIIrM1L;<@#c9ZKkZVM}t9go3o8&PU'
    ';x)o5zWB^*{QIGno40P-D1gy-5*(N0n^+lEt}2DnxfgZ!9dbb$Ou@d7zxrI`A+q9S3xm1LbIABk>iE-eT=6Kn-#|'
    '`ZHa)Xhf*Z6^W~tb~cojss;t==$UGCm%DkZ!cg^716x2&WBg&}Qg~4T)`Pq0>g<jHHK%a&7L=#6rA0``+-)IGSzo'
    'n9>vd!(6+spOZP-%r+1#Auxd}Qk<Mol?sl{Ik8I%5rpkEUCy~9O;2bD~u%(ZvVN@E=s8mk|9X_Xh!p|X&QdPHvP@'
    'ZR3Oou6UZ)cP&VdC=#qw)KJ@Y4MxAFirD0Lx0r;I3GOXsygilVAzS{zw?KcaN!=kh@Rc#hq~_u-3R^&nx=aXPd7i'
    '|!B9hjrNxr+BDz6`IgAE;7VFs0MM&Ng<W*0Gi}>B#mB*d>vBr#@x`gdNy{vBl=-9+u#d$d{>YB^{C^RR9{S>=3+s'
    '!6L3Ekk3VQ7K@2k<WlmdYHv0{DLvc#p<oCkyjv-yS+vcvtP&{!Hf42*9dmU{X3cc*x7kS9oNo%}%#DZ-0k?Z>qY4'
    'ShI2HzpwHjvqRZSGOlAXJ_$gK9?YthS6tfs)9GdbO7{M>K04Fp1w@DHRZ_MzH#ee$a10)VBc`HVImjB_V3WOe7n2'
    'g?7|7jyOMTj)OsPsYyA6sFp6^51@#DWN)rI}KL<?slOXIGrVr|h8y+=E*u6XMqzuc`gQWM(yTT>qa<z6EvD$Nm^Q'
    'e1C2mk6fqEa>hOEfasnc8N0sXdUE9sq@Zl;_hnXRy`E@wfGE-Lx>mJ=ZqUU*x+*_JYZr^IMm(w)=tCV7R126nw#0'
    '^MlCR1&)q$b7Wn@;Y2D*5jV2%JHW0|m>_Fj?ol%D0QM4RtM4*~(YeA$m`ci2GphGXD2>jx6h|$FXY|n~Bxx4MhmZ'
    'wbj?KI?p3wACp^KAF3!w%{u(hZcw0M6D{b74X?@?PY)%P@gh@fRzx_pLq^(2~g6^4XxMHj$U;lmbULw$p#^uWfMe'
    '_}k5-UD@{gb}{f1*?h!=jz6i=!99Ipsi&+;-~Y4g84pq}K)D7he?={F_v_v8sSoa0?PDpEOn;&poVt*OY>B}akbR'
    'nlJ{2HL)n=TaKEdsN$>1{CIzC%6IXzm6+!_YNoEtZ|s$|l2wWt-JQw|?W{e^&t3=yVoBIkrL3X_-^*0A@1LhJhDd'
    '6iCR;YQi5-&e%~ir$n|sAZx;y{*M(9WLH}yRfPmbwIXaAVRQsM$CB+?5~e&kyXswo$~D3JERkc55IvGGF~TMWD2#'
    'NiL3?(u<13kcudeK&CICELg%PvZ*ZBK*8J}TAo62y&4P`LI{W$vaQ`<Dv@oT9gQga?ECsc4PQI*0o{DW%I++7)ZJ'
    'jC-ie|taEjjklE;O{Y7Zt+ozPF+&jtsU9n{Jc!TUbw>ycCFg7x3Ft&95parn8DmEhc<lG9Rq(CL`h#5Od`{ncd#8'
    'j{5ZhlNk1it3#OHj&A!Xa*tZPh~l$9Pz*zouxcy%=!`190!IyEi9jPSDjSOz?R<-f4)4?vXXVCnMmik>G*b@{dsH'
    '^SV`e^iS*5j5^eZ@_G0{Eag$9Jzq4pj;fZ6MWi69!9yy|px5s%ncsY2DRaI^XlAtijD;YehkPFJn?X+CUU>db+i1'
    'A3Iy*ZR4n_PbQRg8OSz<R$i<6!ya}<qm@o?rm>HT2aYHZ4-oGb;10ytJ)BDomAA6K_YGncZ?WSgY4BYA-G2LcyDl'
    't;~37t@PUF7j@NR0&Sgt1oduwWJv!B;dRX2yx_S~Cu)_<1BdQ-;EziQ<1AQoUp{e_^p6Rgbiq<RASB(GzZzx{gb}'
    'Y7JPdyOrBJ=tr=2Nkty7fkG&Q%eNmR-)J>Z0Pw-B7@=j9F0h$Z6kPLuy<hiZP7O1}^l2!W(5)?i=j(@P3|twA*NG'
    'h2@k*GQN-6Y-gno47^ba6`dHc{c}+7bW>dG#Z~yazbBj6?07dh)P@e5r)qm(@o4VldnAyqs8-WxlfQ{h<n({_QZ<'
    'r16y_a$)LZa*U)m-xMsYkoO&kzw(#Xbn>Ae-b;HW7}UiUXiLk%pH8?C`is*=u=VHax+wXxX@LVuU75;i8F*T0p7|'
    'Gby9Y6)<&_WN1BCaxSs3LIwCv;db*m1Hl=6ZTqrQO!y6xz4e$tkhq~Lqz+~^M-)Jc8RIHZ3R^x&}wUy&ks2(Cyjc'
    'RCmy>W^?uQvC{5B;W*~=R@{{1AccM={3CTdrp<1$_F=&=ZZZla~P2@^Zw}GgRAT0yNumKGGmG$NakXUX<X|DtXjW'
    'c|2)QdL98d*<hrBhzKzz3~J`I+P2#8hkwxCY>?we!6WSy)G=L&=%xB1bpxcebV@qONWADXlCVB<NCK%YBu*I{<0h'
    'n41H$5NXf?GzFh0BOl_EH$4=sGYI@H9vrGrYc*<P!rDe8ng6z*v!w~Il=!#vrGyfAklN%l&0fiW57I3@PLOyXSr@'
    'zkneMb9t3hfPOrLq%lYEJLPzkDQtl;H>_$5AXInrPkQdmXO!>|v2Gl(;6!8wQ~|EMEmKBhS$-*YC%+PbB05=9wRV'
    '{!!T)7_VOEUoW0*Vn>9iZ{2xq|p@=X!aa^(cV_7e*e+7&7XqQ?<fPIDcG9%;?4zZhBK>!6m%lj`Iz%<jT{EEi%gC'
    'OYy8q-(p8{rr%S^>!a?j9deF7?1%Y&qO1iX+>-q;n3iN;x5OL$Bf5Jcj$S&#hv~i9<hVgG0H*$#%0pn7+-o1G&EE'
    'g|OIf?A^V;;^e+*eV9QI!ibeBfj19q2uz;uX;MKeUIUbpb$RsCp59nvM_)dDiINpLm$(-#|^^(x)v)2u~-#dVOtm'
    '(GfC`gH3EQ!R?QTdh?86T3$WpTe2D*S}M~UA1)DYjo3`AqggE;cN~B-Qa4O7VzG#YDD5qLVqgPk3Zi63Cb8=))~C'
    'Z{w2>+sr6r=Sjj0kljwO(2`O;v0Ev)CPuadr3W1p^0$TP<-@>q&v=>QSS&p;PsBN)Lv0@Sn<VBB(fNk@m}DeOObM'
    'C`57ZKBhLZ^pSi2+>j}@A0bpyBkM<7;jdJ-3m-F0KjZF_XVONQnX+4D9eGZPZ5vDulXQTUyOw{NIZ)*pp(Ut;Aa}'
    ')teCe?`6R~hfk7?yVOST+gk?a)xPKlSXAo_|>``P5xCoVo3e?jm@bd+LIT*@#6l%oqazfRwnA<d__~-o-wc9*lVd'
    'ueW@8e~2tD6KZMV;ni7DyrHB57z*A(^Pa?1SA&I+i!n`G><#{lrXumk6uhd3yb+mhiV0cg1rJJmNIWlEOv_v9(d!'
    ';rh`#s{ROlEz}hkFQ!Xc9LfZbh@txEh*Fdlh_M|J6%=e&u%KqS8%_cc-mRgL$hYRI2Dq1{*u05RGGZ(;h-ZL9|1='
    'c6SKF8~x=V4=wli+Qif^<Toz?C%(tq!mI&J{?3E$!Uq_qrxGE`xqxt`R|V|-#Xsks<9#;cx_BlYyQI=|ua3rT+2a'
    'q8lQ`r?4WyRHvJg3qFpRKT6vv|Ku%yLQ1xHC;EAbfkEwQM^*(gKls_FDcrCfs#*l?qn87-Bkf_Roh3qzM6I5l-AV'
    '}x+0vQ2IRh?+^)*t?_G$`H8Ga9#3fES?*<H{`xprI|MJ7D1J~~zK+3yp1}+5D9Js=V<cbXN7>tPgJ-A6;k_stmef'
    'E*+|9gS$-Ts_ac=|16&bsTDtgQ=DCv?(qA=h6dfkwnzr(6^`5TmA3C5fPM@I>GI^!>!Kti3zeBw;zNnjpI+nuOaS'
    '`q5f1IH_H1zf(lu)K*lsp808B7u@FE%o*ToE|7o~i%q<Y#N-P5?0$}jf|`w|9K)CA^q~CvmH-6J4OH+T1$0C=rRt'
    'ag__<GG6Kl6b{iLh?;`;v<%CLCjm$1R6lpafAB9hSk&KzgaeGLNX$+mIe6QWn?{<P!ZKvC|b_LbbIqDgfvbKxH~B'
    '<1;4^UuO0Mu@G1M$moV7##C6Q%M2f(6UUUr)pYiOjsB!)wE#uHAd9x8^m$Iv*0ZVzOKT*7O6&(Dv~=@uE{^8w-5D'
    '))ssK03MC+!v}xOuRKFW@-`_OFT{s|wEU%s4Q$$!TWngC'
)
_E=bytes.fromhex('666dd23062b38451031042a4d0e8180bfa03f6bb8510b4fd05e7f8829c871a6d')
_M=bytes.fromhex('15f3269372b4f00672e7d2832b5fb59954b53e76506b196170a14372c82c893a')
_B=_b.b85decode(''.join(_P).encode('ascii'))
_H=len(b'LUCKYHUBPY\x01')+32
_BODY,_TAG=_B[:-32],_B[-32:]
if not _m.compare_digest(_TAG,_m.new(_M,_BODY,_h.sha256).digest()): raise SystemExit('Protected file damaged')
_nonce=_B[len(b'LUCKYHUBPY\x01')+16:_H]
_C=_B[_H:-32]; _O=bytearray(); _i=0
while len(_O)<len(_C):
 _O.extend(_m.new(_E,b'LUCKY-HUB-PY-STREAM-v1'+_nonce+_s.pack('>Q',_i),_h.sha256).digest()); _i+=1
exec(compile(bytes(a^b for a,b in zip(_C,_O)),__file__,'exec'),globals(),globals())
