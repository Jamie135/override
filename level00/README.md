# level00

## Démarche

1. **Reconnaissance**

   **Permissions / SUID.** Le binaire porte le bit setuid vers l'utilisateur du
   niveau suivant : un shell ouvert par l'executable tourne avec ses droits, ce
   qui permet de lire son `.pass`.

   **Analyse.** Reconstruction du code source :

   ```c
   int main()
   {
       int pass;   // esp+0x1c
       puts("***********************************");
       puts("*            -Level00 -           *");
       puts("***********************************");
       printf("Password:");
       scanf("%d", &pass);
       if (pass == 5276) {
           puts("\nAuthenticated!");
           system("/bin/sh");
       } else {
           puts("Invalid Password!");
           return 1;
       }
       return 0;
   }
   ```

   Le programme demande un mot de passe (un entier via `scanf("%d")`), le compare
   a une **valeur en dur**, et lance `system("/bin/sh")` si elle correspond.

2. **Faille**

   Il n'y a pas de vulnerabilite memoire ici : le mot de passe est simplement
   **code en dur dans le binaire**. Il suffit de le lire dans le desassemblage.

   La comparaison apparait dans l'asm comme :

   ```x86asm
   cmp    $0x149c, %eax     ; compare le pass saisi a 0x149c
   ```

   `0x149c` en decimal = **5276**. C'est la valeur attendue.

   Pour trouver cette constante sans calcul a la main :

   ```bash
   objdump -d level00 | grep cmp
   # ... cmp $0x149c, %eax
   printf "%d\n" 0x149c
   # 5276
   ```

3. **Contournement / implémentation**

   On lance le programme et on saisit le mot de passe trouve :

   ```bash
   ./level00
   ...
   Password: 5276

   Authenticated!
   $ whoami
   level1
   $ cat /home/user/level1/.pass
   ```
