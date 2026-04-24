# ESP-Matter Light Source

Ce dossier contient les fichiers source de l'exemple `light` d'ESP-Matter,
copiés depuis le container Docker `hajerrchaieb/matter-light:v1`.

## Contenu

```
esp-matter/
  examples/
    light/
      main/
        app_main.cpp      ← Fichier principal
        app_driver.cpp    ← Pilote LED/PWM
        app_priv.h        ← Headers privés
        CMakeLists.txt    ← Config build
```

## Pourquoi ces fichiers sont dans le repo ?

L'AutoFix Agent (Agent 8) génère des patches unifiés pour ces fichiers.
Le Stage 4c du pipeline applique ces patches, commite sur une branche
`autofix/run-XXX`, et déclenche un nouveau pipeline CI complet.

## Ne pas modifier manuellement

Ces fichiers sont gérés par le pipeline DevSecOps.
Les modifications viennent des patches générés par Agent 8.
