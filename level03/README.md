# level03

## 0. Prérequis

### Le XOR (`^`) et sa réversibilité

Le XOR compare deux bits et renvoie `1` **si et seulement si ils diffèrent** :

```
0^0 = 0     1^1 = 0     0^1 = 1     1^0 = 1
```

La propriété magique, XORer deux fois avec la **même** clé `K` redonne la valeur de départ, fait tout le level :

```
(A ^ B) ^ B = A
```

 > **Rappel**
 >
 > Une lettre comme **"A"** est un juste nombre **(0x41)** en mémoire, donc **XORer** telle lettre avec une clé **"K" (0x12)** revient à faire:
 > ```
 > A ^ K = 0x41 ^ 0x12 = 0100 0001 ^ 0001 0010 
 > ```

Soit **C** un caractère chiffré, **D** un caractère déchiffré (**clair**) et **K** une clé, on sait que:
```
C = D ^ K (chiffré = clair XOR clé)
```
On re-XOR **C** par **D**:
```
C ^ D = (D ^ K) ^ D = K
```
On peut déduire que:
```
K = C ^ D (clé = chiffré ^ clair)
```

## 1. Analyse

### Chaînes essentielles (`.rodata`)

```
0x80489c3  "Congratulations!"     ← cible de comparaison dans decrypt
0x80489d4  "/bin/sh"              ← argument de system() si succès
0x80489dc  "\nInvalid Password"   ← message d'échec
0x8048a7b  "Password:"            ← prompt de main
0x8048a85  "%d"                   ← format scanf de main (entier signé)
```

### `decrypt(key)` — le déchiffrement

```asm
; blob = "Q}|u`sfg~sf{}|a3"  (cf. partie 0)
; len = strlen(blob)                      ; repnz scasb → 16
; pour i de 0 à len :
80486cd:  movzbl (blob+i),%eax
80486d2:  mov    0x8(%ebp),%eax→edx? …     ; eax = key (le paramètre)
80486d5:  xor    %edx,%eax                 ; blob[i] ^ key
80486df:  mov    %dl,(blob+i)              ; blob[i] = blob[i] ^ key
; puis :
8048700:  repz cmpsb                       ; compare blob (déchiffré) à "Congratulations!" (17 o.)
8048711:  test %eax,%eax
8048713:  jne  echec
          system("/bin/sh")                ; si égal
echec:    puts("\nInvalid Password")
```

`decrypt` XOR les 16 octets du blob avec `key`, puis compare le résultat à
`"Congratulations!"`. **Si ça correspond → `system("/bin/sh")`.** La clé `key`
est le paramètre reçu de `test`.

### `test(login, password)` — le sélecteur

```asm
8048755:  index = password - login         ; (arg2 - arg1)
804875c:  cmp  index, 0x15                  ; 21
8048760:  ja   default                     ; si index > 21 (non signé)
8048766:  …    table de saut @0x80489f0    ; switch(index)
```

La table de saut compte 22 entrées. Les index **1–9 et 16–21** mènent chacun à
`decrypt(index)` ; les index **0, 10–15** (et tout `> 21`) tombent dans le
**`default` → `decrypt(rand())`**. Point crucial : dans chaque cas valide, c'est
**`index` lui-même qui est passé à `decrypt`** — l'index est à la fois le
sélecteur du switch **et** la clé de déchiffrement.

### `main`

```asm
srand(time(NULL))
puts(bannière) ×3
printf("Password:")
scanf("%d", &n)                   ; n = ta saisie
test(n, 0x1337d00d)               ; 0x1337d00d = 322424845
```

`main` lit un entier `n` et appelle `test(n, 0x1337d00d)`.

## 2. Reconnaissance

En rassemblant les trois fonctions, le chemin vers `system("/bin/sh")` est :

```
n (saisi)  →  index = 0x1337d00d - n  →  decrypt(index)  →  blob ^ index == "Congratulations!" ?
```

Deux conditions pour gagner :

1. **`index` doit être la bonne clé XOR** (celle qui déchiffre le blob en
   `"Congratulations!"`).
2. **`index` doit être dans `[0,21]` et viser un vrai cas** (sinon `default` →
   `decrypt(rand())`, qui échoue).

### Trouver la clé XOR

On connaît les deux morceaux :
- le texte chiffré, écrit en dur dans le binaire : **`"Q}|usfg~sf{}|a3"`** (donc C = 'Q'` pour le 1er octet) ;
- le texte clair qu'on vise, puisque decrypt compare à **``"Congratulations!"``** (donc D = 'C').

Donc à partir de **0. Prérequis**:

```
K = C ^ D = 'Q' ^ 'C' = 0x51 ^ 0x43 = 0x12 = 18
```

On vérifie que **la même** clé `18` déchiffre tout le blob **`"Q}|usfg~sf{}|a3"`**:

```
0x51^0x12='C'  0x7d^0x12='o'  0x7c^0x12='n'  0x75^0x12='g'
0x60^0x12='r'  0x73^0x12='a'  0x66^0x12='t'  0x67^0x12='u'
0x7e^0x12='l'  0x73^0x12='a'  0x66^0x12='t'  0x7b^0x12='i'
0x7d^0x12='o'  0x7c^0x12='n'  0x61^0x12='s'  0x33^0x12='!'
→ "Congratulations!"
```

La clé est donc **18**. Et `18 ∈ [0,21]`, et l'index 18 est un **vrai cas** de la
table de saut (pas le `default`). Les deux conditions sont satisfaites.

## 3. Exploitation

Il reste à choisir `n` pour que `index = 18` :

```
0x1337d00d - n = 18
n = 0x1337d00d - 18 = 322424845 - 18 = 322424827
```

```sh
$ ./level03
***********************************
*		level03		**
***********************************
Password: 322424827
$ cat /home/users/level04/.pass
```

En entrant **`322424827`** au prompt `Password:`, on obtient `index = 18`, donc
`decrypt(18)` reconstitue `Q}|usfg~sf{}|a3` en `"Congratulations!"`, la comparaison réussit et `system("/bin/sh")` lance un shell avec les droits SUID de level04.
