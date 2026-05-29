# Iteration 4 — Bug Analysis Report (after first run)

## 1. Comportements logiques observés (✅ ce qui marche)

| # | Image | Comportement |
|---|-------|--------------|
| L1 | Image 1, 4, 6 | Lifecycle banner FIRST RUN → second run #25315021695 ✅ |
| L2 | Image 11, 14 | Lifecycle banner SECOND RUN → "applied AutoFix patches from #25312871689" ✅ |
| L3 | Image 7 | Test-Gen run #1: 4 tests générés, 6 edge cases, status `deployed` ✅ |
| L4 | Image 13 | Tests run #2: 4/4 PASS sur host runner, file:line correct ✅ |
| L5 | Image 10 | Diff coloring du patch: `-DEMO_API_KEY = "sk-demo-..."` rouge / `+DEMO_API_KEY = os.environ.get(...)` vert ✅ |
| L6 | Image 11 | TESTS RUN = 4/4 vert au second run → **PREUVE** que les tests générés au run #1 tournent au run #2 ✅ |
| L7 | Image 8 | AutoFix run #1: 1 patch critical (rule_based) sur intentional_bug.py ✅ |
| L8 | Image 16 | Test-Gen second run: même 4 tests deployed (cohérent) ✅ |

**→ La boucle DevSecOps fonctionne de bout en bout.**
**→ Les patches sont visibles dans le PR + visibles dans le second run.**
**→ Les tests générés au run #1 sont bien exécutés au run #2 (preuve: 4/4 PASS).**

---

## 2. Comportements illogiques observés (🔴 bugs)

| # | Image | Bug | Cause racine |
|---|-------|-----|--------------|
| **B1** | Image 1 | Summary run #1: TESTS RUN = 0/0 | Au run #1 les tests n'ont pas encore été déployés → host=no_tests_yet (normal, c'est pour ça qu'on a un run #2) |
| **B2** | Image 2, 3, 14 | **Security 0/10 avec "9 hardcoded secrets"** | Gitleaks scanne tout l'historique git → reporte 9 occurrences du même secret. L'agent ne dédoublonnait pas. |
| **B3** | Image 2 | "PARTIAL — host=no_tests_yet" au run #1 | Normal au run #1, le second run remontera à PASS |
| **B4** | Image 4, 15 | **Code Review = ?/10** au lieu d'un nombre | Le `_extract_score` de l'orchestrator capture le "0 to 10" du prompt template au lieu du score final |
| **B5** | Image 5 | "loading debug-report-{target}.json…" infini | Frontend: le placeholder `{target}` n'était pas résolu avant l'appel API |
| **B6** | Image 6 | Fault Inj. severity = "?" + file = "—" | Frontend: cherche `severity` mais le report v3 utilise un schéma différent |
| **B7** | Image 8, 17, 18, 19 | **13 instructions manuelles IDENTIQUES** | `_collect_issues` itère sur `secrets_found` (9 entrées dupliquées) ET sur les sections markdown du code_review → pas de dédoublonnage |
| **B8** | Image 11 | Pipeline = BLOCKED au second run | Cascade de B2 — Security 0 → errors_found=True → BLOCKED |
| **B9** | Image 17 | "Issues analyzed = 13" au second run | Cascade de B7 |
| **B10** | Image 20 | "Validated by Second Run" pill VIDE | Race condition: `lifecycle()` retourne avant que le pill soit rendu |

---

## 3. Bugs racines (3 corrections font tomber 7 bugs)

| Bug racine | Cascade qu'il résout |
|------------|----------------------|
| **R1** — Dédoublonnage Gitleaks dans `security_agent.py` | B2, B7, B8, B9 |
| **R2** — Score extraction robuste dans `orchestrator.py` | B4 |
| **R3** — Frontend: 4 petits fixes dans `Reports.jsx` | B5, B6, B10, et l'affichage propre des secrets dédupliqués |

---

## 4. Files dans ce bundle

| Fichier | Action | Raison |
|---------|--------|--------|
| `agents/security_agent.py` | **REMPLACER** entièrement | Ajoute Layer 0 (dédoublonnage Gitleaks par `(file, line, rule)`) |
| `agents/AUTOFIX_PATCH.py` | **PATCH PARTIEL** — remplacer uniquement la fonction `_collect_issues` (vers ligne 362) | Dédoublonnage défensif au niveau autofix |
| `agents/ORCHESTRATOR_PATCH.py` | **PATCH PARTIEL** — remplacer uniquement la fonction `_extract_score` (vers ligne 120) | Score extraction robuste pour le code review |
| `dashboard/src/pages/Reports.jsx` | **REMPLACER** entièrement | Tous les fixes frontend + DemoStoryStrip (timeline 5 étapes) |
| `dashboard/src/pages/styles-append-v5.css` | **APPEND** à la fin de `styles.css` | CSS pour la timeline |

---

## 5. Comment appliquer (5 commandes)

```bash
# 1. Replace security_agent.py entirely
cp ~/Downloads/iter4-fixes/agents/security_agent.py \
   ~/DevSecOps-pipline-light-esp32c3/agents/

# 2. Apply autofix _collect_issues patch manually
#    Open agents/autofix_agent.py, find "def _collect_issues(reports: dict)"
#    Replace from there until "return issues" line with content of
#    ~/Downloads/iter4-fixes/agents/AUTOFIX_PATCH.py
#    (only the function body, NOT the docstring at the top of the patch file)

# 3. Apply orchestrator _extract_score patch manually
#    Open supervisor/orchestrator.py, find "def _extract_score(result: dict, *keys)"
#    Replace until the next "def" with content of
#    ~/Downloads/iter4-fixes/agents/ORCHESTRATOR_PATCH.py

# 4. Replace Reports.jsx entirely (in your local dashboard folder)
cp ~/Downloads/iter4-fixes/dashboard/src/pages/Reports.jsx \
   ~/dashboard/frontend/src/pages/

# 5. Append CSS to styles.css
cat ~/Downloads/iter4-fixes/dashboard/src/pages/styles-append-v5.css \
   >> ~/dashboard/frontend/src/styles.css

# 6. Commit + push
cd ~/DevSecOps-pipline-light-esp32c3
git add agents/security_agent.py agents/autofix_agent.py supervisor/orchestrator.py
git commit -m "fix: dedup gitleaks history + robust score extraction + frontend polish"
git push origin main

# 7. Restart Vite (no Flask change needed)
cd ~/dashboard/frontend && npm run dev
```

---

## 6. Résultat attendu après le prochain run

### Run #1 (avec 1 secret intentionnel dans demo/intentional_bug.py)

| Card | Avant (image actuelle) | Après le fix (attendu) |
|------|-----------------------|-------------------------|
| Pipeline | PASSED | PASSED |
| Security score | **0/10** (rouge, justification "9*3 = 27") | **7/10** (orange, justification "1 unique secret found, -3 points") |
| Code Review | **?/10** | **4/10** (la valeur que le LLM produit dans son markdown) |
| Patches | 1 critical | 1 critical |
| Tests gen. | 4 | 4 |
| Tests run | **0/0** (au run #1 c'est normal) | 0/0 (idem, sera 4/4 au run #2) |
| Manual instructions | **13 identiques** | **5-6 uniques** (chaque instruction unique) |
| Demo Story timeline | absent | 🔍 Detect ✅ → 🛠️ Patch ✅ → 📨 PR ✅ → 🔁 Re-run ✅ → ✅ Re-test ✅ |

### Run #2 (qui applique le patch)

| Card | Avant (image actuelle) | Après le fix (attendu) |
|------|-----------------------|-------------------------|
| Pipeline | **BLOCKED** | **PASSED** ✅ |
| Security | **0/10** (cascade) | **10/10** ✅ (le secret a été remplacé par os.environ.get) |
| Code Review | ?/10 | 4/10 |
| Patches | 0 (correct) | 0 (correct) |
| Tests run | 4/4 | 4/4 ✅ |

### Manual Instructions tab (après dédup)

Au lieu de 13 cartes "Hardcoded API key detected" identiques, tu auras:
1. UNE seule "Hardcoded API key detected in intentional_bug.py line 2"
2. "Unsafe functions: strcpy/strcat detected" (du code review)
3. "Buffer risks: fixed-size buffers" (du code review)
4. "Memory leaks: missing free()" (du code review)
5. "Pointer not checked for NULL after allocation" (du fault analysis)

---

## 7. Pour le jury — comment expliquer ces fixes

### Question: "Pourquoi tu as dédoublonné Gitleaks ?"

> "Gitleaks scanne l'historique Git. Quand le même secret apparaît dans
> plusieurs commits — par exemple si je l'ai modifié 9 fois pendant le
> développement — Gitleaks rapporte 9 occurrences. Si on les compte toutes
> comme des secrets distincts, on déduit -27 points pour ce qui est en
> réalité UN seul secret. La déduplication par triplet (fichier, ligne,
> règle) garantit que le score reflète la posture de sécurité actuelle,
> pas l'historique."

### Question: "Tu fais du dédoublonnage à 3 niveaux — c'est pas excessif ?"

> "Non, c'est de la **defense-in-depth**. Le security_agent dédoublonne
> en amont. L'autofix_agent dédoublonne aussi par sécurité, parce que
> le code_review_agent peut produire des bullets qui se recoupent.
> Le frontend dédoublonne UNE FOIS DE PLUS pour le cas où on charge un
> ancien rapport généré avant le fix. Trois couches qui font la même
> chose, c'est ce qui rend le système robuste — exactement comme on
> a fait pour le score de sécurité."

### Question: "À quoi sert la timeline 'Closed-loop' ?"

> "C'est la visualisation centrale de ma contribution. Le PFE n'est
> pas 'détecter des bugs' — beaucoup d'outils font ça. Ma contribution
> c'est **fermer la boucle**: détecter → patcher → PR → re-tester →
> valider. La timeline en 5 étapes rend cette boucle visible en une
> seule capture d'écran. C'est ce que je vais montrer en premier au
> jury."
