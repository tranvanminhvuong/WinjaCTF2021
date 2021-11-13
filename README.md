# WinjaCTF2021
# 1/ Malware

- Tiêu đề file là malware nên mình sẽ k chạy file mà tiến hành decompile nó
- Hàm main()

```cpp
printf("Enter Password\n>>> ");
  scanf("%63s", Str);
  fputs(Buffer, Stream);
  fputc(10, Stream);
  v13 = strlen(Str);
  if ( !strncmp(Str, "00000000", 7ui64) )
    winner();
  smokescreen();
}
```

- Yêu cầu nhập vào password và kiểm tra nếu bằng 0 nhảy tới hàm winner()

```cpp
void __noreturn winner()
{
  size_t v0; // rbx
  char Str[64]; // [rsp+20h] [rbp-60h] BYREF
  char v2[40]; // [rsp+60h] [rbp-20h] BYREF
  int v3; // [rsp+88h] [rbp+8h]
  int i; // [rsp+8Ch] [rbp+Ch]

  strcpy(v2, "qbu~'dkhtb'lbbw'`hni`'hi");
  strcpy(Str, "akf`|600abe0cc7bf15764460Xd7i`u3stX7iXC6aart6i`Xso4Xe7jez");
  for ( i = 0; ; ++i )
  {
    v0 = i;
    if ( v0 > strlen(Str) )
      break;
    v3 = v2[i];
    printf("%c", v3 ^ 7u);
  }
  exit(0);
}
```

- Hàm trả về chuổi v3^7 .Tiến hành xor ta được chuổi

⇒very close keep going on 

- Tiếp tục ta lấy chuổi còn lại xor

```cpp
#include <stdio.h>
#include <string.h>
int main()
{
	char a[]="akf`|600abe0cc7bf15764460Xd7i`u3stX7iXC6aart6i`Xso4Xe7jez";
	int i;
	for(i=0;i<=strlen(a);++i)
	{
		printf("%c",a[i]^7);
	}
	return 1;
}
```

⇒ Flag: flag{177feb7dd0ea62013317_c0ngr4ts_0n_D1ffus1ng_th3_b0mb} 

# 2/Hashmap

- Đọc qua chương trình ta thấy trong hàm main() có hàm main_check_password()

```cpp
if ( (unsigned __int8)main__check_password(v37[0], v37[1]) )
    {
      v34 = L_1305;                             // Access Granted
      v35 = 0x10000000ELL;
      println(L_1305, 0x10000000ELL);
      v22 = L_1307;                             // flag: flag{
      v23 = 11;
      v24 = 1;
      memmove_plt(v25, &v22, 16LL);
      v26 = 65040;
      memset_plt(v27, 0LL, 4LL);
      memmove_plt(v28, v37, 16LL);
      v19 = L_1309;                             // }
      v20 = 1;
      v21 = 1;
      memmove_plt(v29, &v19, 16LL);
      v30 = 0;
      memset_plt(v31, 0LL, 4LL);
      v32 = 0;
      memset_plt(v33, 0LL, 12LL);
      v17 = str_intp(2LL, v25);
      v18 = v11;
      result = println(v17, v11);
    }
```

- Nếu điều kiện hàm check_password thì sẻ thông báo được phép truy cập và in ra flag
- Tiến hành kiểm tra hàm main_check_password

```cpp
if ( (_DWORD)a2 != 58 )
    goto LABEL_60;
  v119 = string_at(a1, a2, 32LL);
  v118 = byte_ascii_str(v119);
  if ( !(unsigned __int8)string__eq(v118, v2, &L_1313, 0x100000001LL) )
    goto LABEL_60;
  v120 = string_at(a1, a2, 36LL);
  v117 = byte_ascii_str(v120);
  if ( !(unsigned __int8)string__eq(v117, v3, &L_1315, 0x100000001LL) )
    goto LABEL_60;
  v121 = string_at(a1, a2, 43LL);
  v116 = byte_ascii_str(v121);
  if ( !(unsigned __int8)string__eq(v116, v4, &L_1317, 0x100000001LL) )
    goto LABEL_60;
  v122 = string_at(a1, a2, 3LL);
  v115 = byte_ascii_str(v122);
  if ( !(unsigned __int8)string__eq(v115, v5, &L_1319, 0x100000001LL) )
    goto LABEL_60;
  v123 = string_at(a1, a2, 21LL);
  v114 = byte_ascii_str(v123);
  if ( !(unsigned __int8)string__eq(v114, v6, &L_1321, 0x100000001LL) )
    goto LABEL_60;
  v124 = string_at(a1, a2, 5LL);
  v113 = byte_ascii_str(v124);
  if ( !(unsigned __int8)string__eq(v113, v7, &L_1323, 0x100000001LL) )
    goto LABEL_60;
  v125 = string_at(a1, a2, 12LL);
  v112 = byte_ascii_str(v125);
  if ( !(unsigned __int8)string__eq(v112, v8, &L_1325, 0x100000001LL) )
    goto LABEL_60;
  v126 = string_at(a1, a2, 50LL);
  v111 = byte_ascii_str(v126);
  if ( !(unsigned __int8)string__eq(v111, v9, &L_1327, 0x100000001LL) )
    goto LABEL_60;
  v127 = string_at(a1, a2, 0LL);
  v110 = byte_ascii_str(v127);
  if ( !(unsigned __int8)string__eq(v110, v10, &L_1329, 0x100000001LL) )
    goto LABEL_60;
  v128 = string_at(a1, a2, 51LL);
  v109 = byte_ascii_str(v128);
  if ( !(unsigned __int8)string__eq(v109, v11, &L_1331, 0x100000001LL) )
    goto LABEL_60;
  v129 = string_at(a1, a2, 48LL);
  v108 = byte_ascii_str(v129);
  if ( !(unsigned __int8)string__eq(v108, v12, &L_1333, 0x100000001LL) )
    goto LABEL_60;
  v130 = string_at(a1, a2, 25LL);
  v107 = byte_ascii_str(v130);
  if ( !(unsigned __int8)string__eq(v107, v13, &L_1335, 0x100000001LL) )
    goto LABEL_60;
  v131 = string_at(a1, a2, 42LL);
  v106 = byte_ascii_str(v131);
  if ( !(unsigned __int8)string__eq(v106, v14, &L_1337, 0x100000001LL) )
    goto LABEL_60;
  v132 = string_at(a1, a2, 38LL);
  v105 = byte_ascii_str(v132);
  if ( !(unsigned __int8)string__eq(v105, v15, &L_1339, 0x100000001LL) )
    goto LABEL_60;
  v133 = string_at(a1, a2, 53LL);
  v104 = byte_ascii_str(v133);
  if ( !(unsigned __int8)string__eq(v104, v16, &L_1341, 0x100000001LL) )
    goto LABEL_60;
  v134 = string_at(a1, a2, 31LL);
  v103 = byte_ascii_str(v134);
  if ( !(unsigned __int8)string__eq(v103, v17, &L_1343, 0x100000001LL) )
    goto LABEL_60;
  v135 = string_at(a1, a2, 28LL);
  v102 = byte_ascii_str(v135);
  if ( !(unsigned __int8)string__eq(v102, v18, &L_1345, 0x100000001LL) )
    goto LABEL_60;
  v136 = string_at(a1, a2, 19LL);
  v101 = byte_ascii_str(v136);
  if ( !(unsigned __int8)string__eq(v101, v19, &L_1347, 0x100000001LL) )
    goto LABEL_60;
  v137 = string_at(a1, a2, 10LL);
  v100 = byte_ascii_str(v137);
  if ( !(unsigned __int8)string__eq(v100, v20, &L_1349, 0x100000001LL) )
    goto LABEL_60;
  v138 = string_at(a1, a2, 8LL);
  v99 = byte_ascii_str(v138);
  if ( !(unsigned __int8)string__eq(v99, v21, &L_1351, 0x100000001LL) )
    goto LABEL_60;
  v139 = string_at(a1, a2, 34LL);
  v98 = byte_ascii_str(v139);
  if ( !(unsigned __int8)string__eq(v98, v22, &L_1353, 0x100000001LL) )
    goto LABEL_60;
  v140 = string_at(a1, a2, 18LL);
  v97 = byte_ascii_str(v140);
  if ( !(unsigned __int8)string__eq(v97, v23, &L_1355, 0x100000001LL) )
    goto LABEL_60;
  v141 = string_at(a1, a2, 57LL);
  v96 = byte_ascii_str(v141);
  if ( !(unsigned __int8)string__eq(v96, v24, &L_1357, 0x100000001LL) )
    goto LABEL_60;
  v142 = string_at(a1, a2, 45LL);
  v95 = byte_ascii_str(v142);
  if ( !(unsigned __int8)string__eq(v95, v25, &L_1359, 0x100000001LL) )
    goto LABEL_60;
  v143 = string_at(a1, a2, 1LL);
  v94 = byte_ascii_str(v143);
  if ( !(unsigned __int8)string__eq(v94, v26, &L_1361, 0x100000001LL) )
    goto LABEL_60;
  v144 = string_at(a1, a2, 27LL);
  v93 = byte_ascii_str(v144);
  if ( !(unsigned __int8)string__eq(v93, v27, &L_1363, 0x100000001LL) )
    goto LABEL_60;
  v145 = string_at(a1, a2, 2LL);
  v92 = byte_ascii_str(v145);
  if ( !(unsigned __int8)string__eq(v92, v28, &L_1365, 0x100000001LL) )
    goto LABEL_60;
  v146 = string_at(a1, a2, 23LL);
  v91 = byte_ascii_str(v146);
  if ( !(unsigned __int8)string__eq(v91, v29, &L_1367, 0x100000001LL) )
    goto LABEL_60;
  v147 = string_at(a1, a2, 29LL);
  v90 = byte_ascii_str(v147);
  if ( !(unsigned __int8)string__eq(v90, v30, &L_1369, 0x100000001LL) )
    goto LABEL_60;
  v148 = string_at(a1, a2, 30LL);
  v89 = byte_ascii_str(v148);
  if ( !(unsigned __int8)string__eq(v89, v31, &L_1371, 0x100000001LL) )
    goto LABEL_60;
  v149 = string_at(a1, a2, 44LL);
  v88 = byte_ascii_str(v149);
  if ( !(unsigned __int8)string__eq(v88, v32, &L_1373, 0x100000001LL) )
    goto LABEL_60;
  v150 = string_at(a1, a2, 56LL);
  v87 = byte_ascii_str(v150);
  if ( !(unsigned __int8)string__eq(v87, v33, &L_1375, 0x100000001LL) )
    goto LABEL_60;
  v151 = string_at(a1, a2, 49LL);
  v86 = byte_ascii_str(v151);
  if ( !(unsigned __int8)string__eq(v86, v34, &L_1377, 0x100000001LL) )
    goto LABEL_60;
  v152 = string_at(a1, a2, 15LL);
  v85 = byte_ascii_str(v152);
  if ( !(unsigned __int8)string__eq(v85, v35, &L_1379, 0x100000001LL) )
    goto LABEL_60;
  v153 = string_at(a1, a2, 40LL);
  v84 = byte_ascii_str(v153);
  if ( !(unsigned __int8)string__eq(v84, v36, &L_1381, 0x100000001LL) )
    goto LABEL_60;
  v154 = string_at(a1, a2, 52LL);
  v83 = byte_ascii_str(v154);
  if ( !(unsigned __int8)string__eq(v83, v37, &L_1383, 0x100000001LL) )
    goto LABEL_60;
  v155 = string_at(a1, a2, 20LL);
  v82 = byte_ascii_str(v155);
  if ( !(unsigned __int8)string__eq(v82, v38, &L_1385, 0x100000001LL) )
    goto LABEL_60;
  v156 = string_at(a1, a2, 54LL);
  v81 = byte_ascii_str(v156);
  if ( !(unsigned __int8)string__eq(v81, v39, &L_1387, 0x100000001LL) )
    goto LABEL_60;
  v157 = string_at(a1, a2, 11LL);
  v80 = byte_ascii_str(v157);
  if ( !(unsigned __int8)string__eq(v80, v40, &L_1389, 0x100000001LL) )
    goto LABEL_60;
  v158 = string_at(a1, a2, 47LL);
  v79 = byte_ascii_str(v158);
  if ( !(unsigned __int8)string__eq(v79, v41, &L_1391, 0x100000001LL) )
    goto LABEL_60;
  v159 = string_at(a1, a2, 24LL);
  v78 = byte_ascii_str(v159);
  if ( !(unsigned __int8)string__eq(v78, v42, &L_1393, 0x100000001LL) )
    goto LABEL_60;
  v160 = string_at(a1, a2, 33LL);
  v77 = byte_ascii_str(v160);
  if ( !(unsigned __int8)string__eq(v77, v43, &L_1395, 0x100000001LL) )
    goto LABEL_60;
  v161 = string_at(a1, a2, 26LL);
  v76 = byte_ascii_str(v161);
  if ( !(unsigned __int8)string__eq(v76, v44, &L_1397, 0x100000001LL) )
    goto LABEL_60;
  v162 = string_at(a1, a2, 14LL);
  v75 = byte_ascii_str(v162);
  if ( !(unsigned __int8)string__eq(v75, v45, &L_1399, 0x100000001LL) )
    goto LABEL_60;
  v163 = string_at(a1, a2, 16LL);
  v74 = byte_ascii_str(v163);
  if ( !(unsigned __int8)string__eq(v74, v46, &L_1401, 0x100000001LL) )
    goto LABEL_60;
  v164 = string_at(a1, a2, 13LL);
  v73 = byte_ascii_str(v164);
  if ( !(unsigned __int8)string__eq(v73, v47, &L_1403, 0x100000001LL) )
    goto LABEL_60;
  v165 = string_at(a1, a2, 46LL);
  v72 = byte_ascii_str(v165);
  if ( !(unsigned __int8)string__eq(v72, v48, &L_1405, 0x100000001LL) )
    goto LABEL_60;
  v166 = string_at(a1, a2, 22LL);
  v71 = byte_ascii_str(v166);
  if ( !(unsigned __int8)string__eq(v71, v49, &L_1407, 0x100000001LL) )
    goto LABEL_60;
  v167 = string_at(a1, a2, 6LL);
  v70 = byte_ascii_str(v167);
  if ( !(unsigned __int8)string__eq(v70, v50, &L_1409, 0x100000001LL) )
    goto LABEL_60;
  v168 = string_at(a1, a2, 7LL);
  v69 = byte_ascii_str(v168);
  if ( !(unsigned __int8)string__eq(v69, v51, &L_1411, 0x100000001LL) )
    goto LABEL_60;
  v169 = string_at(a1, a2, 55LL);
  v68 = byte_ascii_str(v169);
  if ( !(unsigned __int8)string__eq(v68, v52, &L_1413, 0x100000001LL) )
    goto LABEL_60;
  v170 = string_at(a1, a2, 4LL);
  v67 = byte_ascii_str(v170);
  if ( !(unsigned __int8)string__eq(v67, v53, &L_1415, 0x100000001LL) )
    goto LABEL_60;
  v171 = string_at(a1, a2, 17LL);
  v66 = byte_ascii_str(v171);
  if ( !(unsigned __int8)string__eq(v66, v54, &L_1417, 0x100000001LL) )
    goto LABEL_60;
  v172 = string_at(a1, a2, 35LL);
  v65 = byte_ascii_str(v172);
  if ( !(unsigned __int8)string__eq(v65, v55, &L_1419, 0x100000001LL) )
    goto LABEL_60;
  v173 = string_at(a1, a2, 37LL);
  v64 = byte_ascii_str(v173);
  if ( !(unsigned __int8)string__eq(v64, v56, &L_1421, 0x100000001LL) )
    goto LABEL_60;
  v174 = string_at(a1, a2, 41LL);
  v63 = byte_ascii_str(v174);
  if ( (unsigned __int8)string__eq(v63, v57, &L_1423, 0x100000001LL)
    && (v175 = string_at(a1, a2, 9LL),
        v62 = byte_ascii_str(v175),
        (unsigned __int8)string__eq(v62, v58, &L_1425, 0x100000001LL))
    && (v176 = string_at(a1, a2, 39LL),
        v61 = byte_ascii_str(v176),
        (unsigned __int8)string__eq(v61, v59, &L_1427, 0x100000001LL)) )
  {
    LOBYTE(result) = 1;
  }
  else
  {
LABEL_60:
    LOBYTE(result) = 0;
  }
  return (unsigned __int8)result;
}
```

- Nếu vược qua tất cả điều kiện thì hàm sẻ return 1; ngược lại return 0

```cpp
if ( (_DWORD)a2 != 58 )                       // Số phần tử của mảng input = 58
    goto LABEL_60;
  v119 = string_at(a1, a2, 32LL);               // Lấy phần tử tại vị trí 32 của mảng input
  v118 = byte_ascii_str(v119);                  // chuyển sang str
  if ( !(unsigned __int8)string__eq(v118, v2, &L_1313, 0x100000001LL) )// kiểm tra v188 và L_1313
```

- Tất cả các điều kiện sau lặp lại như vậy cho đến khi kết thúc.

```cpp
L_1315          db  61h ; a             ; DATA XREF: main__check_password+DD↑o
.data:00000000006AD897                 db    0
.data:00000000006AD898 L_1317          db  65h ; e             ; DATA XREF: main__check_password+163↑o
.data:00000000006AD899                 align 2
.data:00000000006AD89A L_1319          db  32h ; 2             ; DATA XREF: main__check_password+1EC↑o
.data:00000000006AD89B                 db    0
.data:00000000006AD89C L_1321          db  39h ; 9             ; DATA XREF: main__check_password+28A↑o
.data:00000000006AD89D                 align 2
.data:00000000006AD89E L_1323          db  64h ; d             ; DATA XREF: main__check_password+32B↑o
.data:00000000006AD89F                 db    0
.data:00000000006AD8A0 L_1325          db  62h ; b             ; DATA XREF: main__check_password+3CC↑o
.data:00000000006AD8A1                 align 2
.data:00000000006AD8A2 L_1327          db  68h ; h             ; DATA XREF: main__check_password+46D↑o
.data:00000000006AD8A3                 db    0
.data:00000000006AD8A4 L_1329          db  63h ; c             ; DATA XREF: main__check_password+50E↑o
.data:00000000006AD8A5                 align 2
.data:00000000006AD8A6 L_1331          db  61h ; a             ; DATA XREF: main__check_password+5AF↑o
.data:00000000006AD8A7                 db    0
.data:00000000006AD8A8 L_1333          db  5Fh ; _             ; DATA XREF: main__check_password+650↑o
.data:00000000006AD8A9                 align 2
.data:00000000006AD8AA L_1335          db  66h ; f             ; DATA XREF: main__check_password+6F1↑o
.data:00000000006AD8AB                 db    0
.data:00000000006AD8AC L_1337          db  6Ch ; l             ; DATA XREF: main__check_password+792↑o
.data:00000000006AD8AD                 align 2
.data:00000000006AD8AE L_1339          db  35h ; 5             ; DATA XREF: main__check_password+833↑o
.data:00000000006AD8AF                 db    0
.data:00000000006AD8B0 L_1341          db  34h ; 4             ; DATA XREF: main__check_password+8D4↑o
.data:00000000006AD8B1                 align 2
.data:00000000006AD8B2 L_1343          db  30h ; 0             ; DATA XREF: main__check_password+975↑o
.data:00000000006AD8B3                 db    0
.data:00000000006AD8B4 L_1345          db  61h ; a             ; DATA XREF: main__check_password+A16↑o
.data:00000000006AD8B5                 align 2
.data:00000000006AD8B6 L_1347          db  66h ; f             ; DATA XREF: main__check_password+AB7↑o
.data:00000000006AD8B7                 db    0
.data:00000000006AD8B8 L_1349          db  36h ; 6             ; DATA XREF: main__check_password+B58↑o
.data:00000000006AD8B9                 align 2
.data:00000000006AD8BA L_1351          db  34h ; 4             ; DATA XREF: main__check_password+BF9↑o
.data:00000000006AD8BB                 db    0
.data:00000000006AD8BC L_1353          db  31h ; 1             ; DATA XREF: main__check_password+C9A↑o
.data:00000000006AD8BD                 align 2
.data:00000000006AD8BE L_1355          db  64h ; d             ; DATA XREF: main__check_password+D3B↑o
.data:00000000006AD8BF                 db    0
.data:00000000006AD8C0 L_1357          db  72h ; r             ; DATA XREF: main__check_password+DDC↑o
.data:00000000006AD8C1                 align 2
.data:00000000006AD8C2 L_1359          db  74h ; t             ; DATA XREF: main__check_password+E7D↑o
.data:00000000006AD8C3                 db    0
.data:00000000006AD8C4 L_1361          db  39h ; 9             ; DATA XREF: main__check_password+F1E↑o
.data:00000000006AD8C5                 align 2
.data:00000000006AD8C6 L_1363          db  35h ; 5             ; DATA XREF: main__check_password+FBF↑o
.data:00000000006AD8C7                 db    0
.data:00000000006AD8C8 L_1365          db  31h ; 1             ; DATA XREF: main__check_password+1060↑o
.data:00000000006AD8C9                 align 2
.data:00000000006AD8CA L_1367          db  36h ; 6             ; DATA XREF: main__check_password+1101↑o
.data:00000000006AD8CB                 db    0
.data:00000000006AD8CC L_1369          db  64h ; d             ; DATA XREF: main__check_password+11A2↑o
.data:00000000006AD8CD                 align 2
.data:00000000006AD8CE L_1371          db  38h ; 8             ; DATA XREF: main__check_password+1243↑o
.data:00000000006AD8CF                 db    0
.data:00000000006AD8D0 L_1373          db  5Fh ; _             ; DATA XREF: main__check_password+12E4↑o
.data:00000000006AD8D1                 align 2
.data:00000000006AD8D2 L_1375          db  45h ; E             ; DATA XREF: main__check_password+1385↑o
.data:00000000006AD8D3                 db    0
.data:00000000006AD8D4 L_1377          db  63h ; c             ; DATA XREF: main__check_password+1426↑o
.data:00000000006AD8D5                 align 2
.data:00000000006AD8D6 L_1379          db  33h ; 3             ; DATA XREF: main__check_password+14C7↑o
.data:00000000006AD8D7                 db    0
.data:00000000006AD8D8 L_1381          db  4Dh ; M             ; DATA XREF: main__check_password+1568↑o
.data:00000000006AD8D9                 align 2
.data:00000000006AD8DA L_1383          db  72h ; r             ; DATA XREF: main__check_password+1609↑o
.data:00000000006AD8DB                 db    0
.data:00000000006AD8DC L_1385          db  36h ; 6             ; DATA XREF: main__check_password+16AA↑o
.data:00000000006AD8DD                 align 2
.data:00000000006AD8DE L_1387          db  63h ; c             ; DATA XREF: main__check_password+174B↑o
.data:00000000006AD8DF                 db    0
.data:00000000006AD8E0 L_1389          db  31h ; 1             ; DATA XREF: main__check_password+17EC↑o
.data:00000000006AD8E1                 align 2
.data:00000000006AD8E2 L_1391          db  65h ; e             ; DATA XREF: main__check_password+188D↑o
.data:00000000006AD8E3                 db    0
.data:00000000006AD8E4 L_1393          db  36h ; 6             ; DATA XREF: main__check_password+192E↑o
.data:00000000006AD8E5                 align 2
.data:00000000006AD8E6 L_1395          db  64h ; d             ; DATA XREF: main__check_password+19CF↑o
.data:00000000006AD8E7                 db    0
.data:00000000006AD8E8 L_1397          db  31h ; 1             ; DATA XREF: main__check_password+1A70↑o
.data:00000000006AD8E9                 align 2
.data:00000000006AD8EA L_1399          db  30h ; 0             ; DATA XREF: main__check_password+1B11↑o
.data:00000000006AD8EB                 db    0
.data:00000000006AD8EC L_1401          db  30h ; 0             ; DATA XREF: main__check_password+1BB2↑o
.data:00000000006AD8ED                 align 2
.data:00000000006AD8EE L_1403          db  36h ; 6             ; DATA XREF: main__check_password+1C53↑o
.data:00000000006AD8EF                 db    0
.data:00000000006AD8F0 L_1405          db  48h ; H             ; DATA XREF: main__check_password+1CF4↑o
.data:00000000006AD8F1                 align 2
.data:00000000006AD8F2 L_1407          db  31h ; 1             ; DATA XREF: main__check_password+1D95↑o
.data:00000000006AD8F3                 db    0
.data:00000000006AD8F4 L_1409          db  39h ; 9             ; DATA XREF: main__check_password+1E36↑o
.data:00000000006AD8F5                 align 2
.data:00000000006AD8F6 L_1411          db  65h ; e             ; DATA XREF: main__check_password+1ED7↑o
.data:00000000006AD8F7                 db    0
.data:00000000006AD8F8 L_1413          db  54h ; T             ; DATA XREF: main__check_password+1F78↑o
.data:00000000006AD8F9                 align 2
.data:00000000006AD8FA L_1415          db  65h ; e             ; DATA XREF: main__check_password+2019↑o
.data:00000000006AD8FB                 db    0
.data:00000000006AD8FC L_1417          db  62h ; b             ; DATA XREF: main__check_password+20BA↑o
.data:00000000006AD8FD                 align 2
.data:00000000006AD8FE L_1419          db  53h ; S             ; DATA XREF: main__check_password+215B↑o
.data:00000000006AD8FF                 db    0
.data:00000000006AD900 L_1421          db  73h ; s             ; DATA XREF: main__check_password+21FC↑o
.data:00000000006AD901                 align 2
.data:00000000006AD902 L_1423          db  62h ; b             ; DATA XREF: main__check_password+229D↑o
.data:00000000006AD903                 db    0
.data:00000000006AD904 L_1425          db  66h ; f             ; DATA XREF: main__check_password+233E↑o
.data:00000000006AD905                 db    0
.data:00000000006AD906 L_1427          db  33h ; 3
```

- Lấy data và tiến hành lấy flag

```cpp
#include <stdio.h>
#include <string.h>
int main()
{
	char b[]="_ae29dbhca_fl540af641drt9516d8_Ec3Mr6c1e6d1006H19eTebSsbf3";
  	int c[]={32,36,43,3,21,5,12,50,0,51,48,25,42,38,53,31,28,19,10,8,34,18,57,45,1,27,2,23,29,30,44,56,49,15,40,52,20,54,11,47,24,33,26,14,16,13,46,22,6,7,55,4,17,35,37,41,9,39};
	int i,j;
	printf("flag{");
	for(i=0;i<58;i++)
	{
		for(j=0;j<58;++j)
		{
			if(c[j]==i)
		  		printf("%c",b[j]);
		}
    
	}
	printf("}");
	return 1;
}
```

⇒Flag : flag{c912ed9e4f61b6030bdf69166f15ad80_d1Sas53Mble_tHe_char4cTEr}
