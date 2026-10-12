# level06

## 1. Analyse

### Ce que fait `main`

```asm
printf("-> Enter Login: ")
fgets(login, 0x20, stdin)        ; login = chaîne (32 o. max), à 0x2c(%esp)
printf("-> Enter Serial: ")
scanf("%u", &serial)             ; serial = entier NON signé, à 0x28(%esp)
call auth                        ; auth(login, serial)
test %eax,%eax
jne  echec
; succès (auth == 0) :
puts("Authenticated!")
system("/bin/sh")                ; 0x8048b61
```

`main` lit un **login** et un **serial**, appelle `auth(login, serial)`, et si
`auth` renvoie `0` → `system("/bin/sh")`. Tout se joue donc dans `auth`.

### `auth` : les gardes puis le calcul

**Garde 1 — longueur du login :**
```asm
call strnlen(login, 0x20)        ; len = strnlen(login, 32)
cmpl $0x5,-0xc(%ebp)
jg   suite                       ; len > 5 requis
mov  $0x1,%eax ; return 1         ; sinon → échec
```
→ le login doit faire **au moins 6 caractères**.

**Garde 2 — anti-debug (`ptrace`) :**
```asm
80487b5: call ptrace(PTRACE_TRACEME,0,1,0)
80487ba: cmp  $0xffffffff,%eax
80487bd: jne  80487ed                     ; != -1 → OK, saute au calcul du hash
         ; == -1 → "!! TAMPERING DETECTED !!" ; return 1
80487ed: (début du calcul du hash)         ; branche "non tracé"
```
→ si le programme est **déjà tracé** (gdb, ltrace, strace…), `PTRACE_TRACEME`
renvoie `-1` et `auth` échoue. C'est ce qui empêche de lire le serial « en
direct » sous debugger. Retiens les deux adresses : **`0x80487b5`** (le `call`)
et **`0x80487ed`** (la suite « non tracé ») — on sautera de l'une à l'autre en
partie 3 pour neutraliser cet anti-debug.

**Le hash — graine puis boucle :** (`hash` vit en **`-0x10(%ebp)`**)
```asm
; graine à partir du 4e caractère du login (login[3]) :
80487ed: movsbl login[3],%eax
80487f9: xor  $0x1337,%eax
80487fe: add  $0x5eeded,%eax
8048803: mov  %eax,-0x10(%ebp)   ; hash = (login[3] ^ 0x1337) + 0x5eeded

; pour i de 0 à len-1 :
movzbl login[i],%eax
cmp  $0x1f,%al ; jg …            ; garde 3 : chaque login[i] doit être > 31
...
movsbl login[i],%eax
xor  -0x10(%ebp),%eax            ; (login[i] ^ hash)
...                              ; division magique par 0x539 = 1337
                                 ; → reste = (login[i] ^ hash) % 1337
add  %eax,-0x10(%ebp)            ; hash += (login[i] ^ hash) % 1337
```

**La comparaison finale :** (le hash est complet à partir d'ici)
```asm
8048863: mov  0xc(%ebp),%eax     ; serial
8048866: cmp  -0x10(%ebp),%eax   ; serial == hash ?  ← hash prêt en -0x10(%ebp)
8048869: je   ok  → return 0     ; succès
                  → return 1     ; sinon échec
```

> Ces deux faits — `hash` est en **`-0x10(%ebp)`**, et il est **complet au
> `cmp` de `0x8048866`** — sont exactement ce qu'on exploite en partie 3 :
> on s'arrête à `0x8048866` et on lit `-0x10(%ebp)`.

### Synthèse — l'algorithme du serial

```c
hash = (login[3] ^ 0x1337) + 0x5eeded;          // 0x1337=4919, 0x5eeded=6221293
for (i = 0; i < len; i++)
    hash += (login[i] ^ hash) % 1337;           // tout en NON signé
serial_valide = hash;
```
avec les contraintes : `len > 5`, et chaque `login[i]` imprimable
(`> 31`, donc 32–127).

## 2. Reconnaissance

### Origine de la « faille »

La « faille » n'est pas une corruption mémoire : c'est que **le serial est une
fonction déterministe et publique du login** (un *keygenme*). Aucun secret
n'intervient → on reproduit le calcul hors-ligne et on **forge** le serial.

### Ce qu'il faut pour l'exploitation

1. **Reproduire exactement** le hash : la graine `(login[3]^0x1337)+0x5eeded`, la
   boucle `hash += (login[i]^hash) % 1337`, le tout en arithmétique **non
   signée** (le binaire divise en non signé) et avec `login[i]` traité comme
   `signed char` dans les XOR.
2. **Respecter les contraintes** sur le login (≥ 6 caractères, tous imprimables).
3. **Gérer `ptrace`** : soit on calcule le serial hors-ligne (pas de debugger),
   soit, si on veut laisser le binaire le calculer sous gdb, on **saute
   par-dessus** le `call ptrace`.

Deux approches donc : un **keygen** (reproduire l'algo), ou **laisser le binaire
calculer le hash sous gdb** et le lire en mémoire. C'est cette seconde méthode,
plus rapide, qu'on détaille en partie 3.

## 3. Exploitation

On choisit un login quelconque valide (≥ 6 caractères, imprimables), par ex.
`EZCRACK`, et on laisse `auth` calculer son hash — en neutralisant l'anti-debug.

### Récupérer le serial sous gdb

```gdb
$ gdb ./level06
(gdb) break *0x080487b5      # sur le call ptrace (l'anti-debug)

...

(gdb) break *0x08048866      # sur la comparaison entre serial et hash (hash calculé après la boucle)

...

(gdb) run

...
-> Enter Login: EZCRACK
-> Enter Serial: 0        # n'importe

Breakpoint 1, 0x080487b5 in auth ()
(gdb) jump *0x080487ed    # saute PAR-DESSUS le ptrace → branche "non tracé"
Continuing at 0x80487ed.

Breakpoint 2, 0x08048866 in auth ()
(gdb) print *(int*)($ebp-0x10)
$1 = 6230032              # = le serial valide pour "EZCRACK"
```

- **Breakpoint `0x080487b5`** : on s'arrête sur le `call ptrace`. Si on le laissait
  s'exécuter sous gdb, il renverrait `-1` (process tracé) → « TAMPERING
  DETECTED ». 
- **`jump *0x080487ed`** : on passe directement à la première instruction du
  calcul du hash, sautant le `call ptrace` et son test → **anti-debug
  neutralisé**.
- **Breakpoint `0x08048866`** : on y arrive une fois la boucle finie ; `hash` (en `-0x10(%ebp)`) est calculé et comparé à serial.
- **`print *(int*)($ebp-0x10)`** : on lit ce hash → **`6230032`**.

### Authentification

Hors gdb (donc `ptrace` réussit normalement), on fournit le même login et le
serial trouvé :

```sh
$ ./level06
-> Enter Login: EZCRACK
-> Enter Serial: 6230032
Authenticated!
$ cat /home/users/level07/.pass
GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8
```
