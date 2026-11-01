# rtp-bff

**Backend-for-Frontend (BFF) für Rock the Prototype – als iterativ prototypisch entwickeltes, überprüfbares Architekturartefakt.**

`rtp-bff` ist ein in Rust implementierter Backend-for-Frontend-Prototyp für **Rock the Prototype**. Das Repository verbindet föderierte Authentifizierung über **OpenID Connect / Keycloak** mit serverseitigem Session-Management über **Redis** und einer kontrollierten Proxy-Grenze zu geschützten Ressourcen.

Im Mittelpunkt steht nicht nur die technische Funktion. Das Repository dient zugleich als öffentlich nachvollziehbares Lern- und Evidenzartefakt: Architekturannahmen werden in kleine, prüfbare Inkremente zerlegt, im Code umgesetzt, durch Tests abgesichert und anschließend weiterentwickelt.

> **Leitidee:** Nicht zuerst die vollständige Zielarchitektur behaupten, sondern relevante Eigenschaften schrittweise prototypisch herstellen und nachweisbar machen.

## Warum ein BFF?

Der Browser soll weder OAuth-/OIDC-Tokens verwalten noch selbst Vertrauensentscheidungen treffen müssen. Das BFF bildet deshalb eine bewusst kontrollierte Grenze zwischen Browser, Identity Provider und nachgelagerten Ressourcen.

Der aktuelle Ansatz folgt dabei insbesondere diesen Prinzipien:

- Der Browser erhält nur ein **opakes Session-Cookie**.
- Access-, Refresh- und ID-Tokens verbleiben **serverseitig**.
- OIDC-Authentifizierung wird über einen **confidential client** mit Authorization Code Flow und PKCE abgewickelt.
- ID Tokens werden kryptographisch geprüft; die akzeptierte Signaturalgorithmik ist bewusst eingeschränkt.
- Eine authentifizierte Identität wird intern über **`(issuer, subject)`** verankert – nicht über eine E-Mail-Adresse.
- Optionale Profilattribute wie `email` und `email_verified` werden über **UserInfo** angereichert und an das bereits verifizierte `subject` gebunden.
- Ein Token-Refresh darf die bereits etablierte Identität **nicht verändern**.
- Session-Zustand wird serverseitig in Redis gehalten; konkurrierende Refresh-Vorgänge werden kontrolliert und fail-closed behandelt.
- Der Proxy-Pfad folgt einem **deny-by-default**-Ansatz und erlaubt nur explizit modellierte Ressourcen und Methoden.

## Aktuelle Vertrauenskette

```text
Browser
  │
  │  opaque session cookie
  ▼
Rust BFF
  │
  ├── Authorization Code + PKCE
  ▼
OIDC / Keycloak
  │
  ├── ID Token ───────► Signatur + Issuer + Audience + Nonce + Subject prüfen
  │
  └── Access Token ───► UserInfo
                           │
                           └── UserInfo.sub muss dem verifizierten Subject entsprechen

Rust BFF
  │
  ├── SessionIdentity
  │     ├── issuer
  │     ├── subject
  │     ├── email? 
  │     └── email_verified?
  │
  └── OAuth-Material + Identity serverseitig in Redis

Browser sieht keine OAuth-Tokens.
```

Damit wird bewusst zwischen mehreren Ebenen unterschieden:

```text
Account / Contact
        ≠
Personenidentität
        ≠
Vertretungsbefugnis einer Organisation
        ≠
Qualifikation / Capability
        ≠
Berechtigung / Entitlement
```

`email_verified = true` ist daher beispielsweise **kein universeller Identitätsnachweis**. Es ist lediglich Evidenz dafür, dass der Identity Provider die Kontrolle über eine bestimmte E-Mail-Adresse bestätigt hat.

## Iterativ prototypische Vorgehensweise

Dieses Repository versteht Prototyping nicht als Wegwerf-Code, sondern als Methode zur kontrollierten Erkenntnisgewinnung.

Ein Inkrement folgt idealerweise diesem Zyklus:

```text
Problem / Hypothese
        ↓
Architekturentscheidung
        ↓
Akzeptanzkriterium
        ↓
kleinste wirksame Implementierung
        ↓
automatisierter Test / technische Evidenz
        ↓
Erkenntnis über Wirkung und Grenzen
        ↓
nächstes Inkrement
```

Beispiele aus der bisherigen Entwicklung:

- Sessions wurden zunächst ausschließlich serverseitig etabliert, damit Tokens den Browser nicht erreichen.
- Redis wurde nicht nur als Speicher ergänzt, sondern um explizite Session-Felder und kontrollierte Refresh-Mutationen erweitert.
- Die authentifizierte Identität wurde anschließend als eigenes Modell eingeführt.
- ID-Token-Verifikation liefert nun das verifizierte Subject statt nur eines booleschen Erfolgszustands.
- UserInfo ergänzt optionale Kontaktattribute, ohne die Identitätsverankerung auf E-Mail zu reduzieren.
- Tests modellieren inzwischen auch einen vollständigen Mock-OIDC-Provider mit Discovery, JWKS, Token- und UserInfo-Endpunkt.

Die Tests sind damit nicht nur Regression Protection, sondern Teil der **nachvollziehbaren Evidenzkette** für die jeweils behaupteten Sicherheitseigenschaften.

## Vom Login zur Rock-the-Prototype-Plattform

Der BFF ist kein Selbstzweck. Er bildet eine technische Grundlage für einen späteren Rock-the-Prototype-Flow:

```text
Discover → Contribute → Prove → Impact
```

bzw. als fortlaufender Wirkungszyklus:

```text
Problem → People → Contribution → Evidence → Outcome → Reputation → next Problem
```

Die Identitätsschicht ist dafür bewusst nur eine Dimension. Spätere Inkremente können darauf aufbauend beispielsweise Fähigkeiten, Nachweise, Beiträge, Reputation und Berechtigungen modellieren, ohne diese Konzepte mit dem Login selbst zu vermischen.

## Architekturprinzipien

### Tokens bleiben serverseitig

Das BFF verhindert bewusst, dass OAuth-Tokens im Browser als Anwendungszustand verfügbar sind. Der Browser arbeitet ausschließlich mit der BFF-Session.

### Identität ist mehr als eine E-Mail-Adresse

Der interne Anchor ist `(issuer, subject)`. Weitere Claims sind Attribute mit eigener Semantik und Evidenzstärke.

### Refresh erneuert Credentials – nicht Identität

Ein Refresh kann Access- und Refresh-Tokens aktualisieren. Die bereits etablierte `SessionIdentity` bleibt unverändert, bis die Session endet und eine neue Authentifizierung stattfindet.

### Fail closed

Fehler bei Token-Prüfung, Provider-Kommunikation, Session-Persistenz oder konkurrierender Refresh-Koordination führen nicht zu einem impliziten Vertrauensgewinn.

### Explizite Grenzen statt impliziter Weiterleitung

Der Proxy akzeptiert nur explizit modellierte Routen, Methoden und relevante Parameter. Unbekannte oder nicht freigegebene Zugriffe werden standardmäßig abgelehnt.

## Qualität und Tests

Vor einem Commit bzw. Pull Request sollten mindestens folgende Checks lokal erfolgreich sein:

```bash
cargo fmt --check
cargo check --tests
cargo test
```

Redis-spezifische Integrationstests sind separat ausführbar, sobald eine Testinstanz über `RTP_REDIS_INTEGRATION_URL` verfügbar ist.

Die Tests decken unter anderem ab:

- OIDC-Transaktionsbindung und Replay-Schutz,
- PKCE,
- Nonce-, Signatur- und Algorithmusprüfung,
- JWKS-Rotation,
- confidential-client Authentifizierung,
- Session- und Cookie-Verhalten,
- Token-Refresh und konkurrierende Refresh-Vorgänge,
- Erhalt der authentifizierten Identität beim Refresh,
- kontrollierte Proxy-Routen und Header-Grenzen,
- UserInfo-Bindung an das verifizierte Subject.

## Repository als öffentliches Lernartefakt

Rock the Prototype verfolgt den Ansatz, technische Überlegungen nicht nur zu beschreiben, sondern möglichst als **versionierte, maschinenlesbare und überprüfbare Artefakte** sichtbar zu machen.

Dieses Repository ist deshalb zugleich:

- ausführbarer Prototyp,
- Architekturartefakt,
- Test- und Evidenzbasis,
- Ausgangspunkt für weitere Iterationen.

Nicht jeder Commit stellt einen endgültigen Zielzustand dar. Entscheidend ist, dass die Entwicklungsschritte, Annahmen und überprüfbaren Eigenschaften nachvollziehbar bleiben.

## Kontext: Large-Scale Agile, Datenqualität und Regulatorik

Die Vorgehensweise steht in einem größeren methodischen Kontext. Besonders relevant sind drei Kapitel, die unterschiedliche Perspektiven auf dieselbe Grundidee eröffnen: komplexe Anforderungen schrittweise in wirksame, überprüfbare Umsetzung zu überführen.

- [Wie Sie ein Large-Scale Agile Framework anpassen und in Ihrer Organisation einführen](https://link.springer.com/chapter/10.1007/978-3-662-73649-4_4)  
  Relevant für die Frage, wie Prinzipien und Frameworks nicht schematisch übernommen, sondern kontextbezogen angepasst und iterativ operationalisiert werden.

- [Datenqualität – Lebenselixier der Digitalisierung](https://link.springer.com/chapter/10.1007/978-3-662-73649-4_8)  
  Relevant, weil digitale Entscheidungen und Vertrauensmodelle nur so belastbar sind wie die Semantik, Herkunft und Qualität der zugrunde liegenden Daten und Claims.

- [Regulatorik & Agilität – Vom Gesetz zur Umsetzung in Large-Scale Agile](https://link.springer.com/chapter/10.1007/978-3-662-73649-4_9)  
  Relevant für die Überführung abstrakter regulatorischer und sicherheitsbezogener Anforderungen in konkrete Architekturentscheidungen, Akzeptanzkriterien und nachweisbare technische Eigenschaften.

Der BFF ist damit ein kleines, konkretes Beispiel für ein größeres Muster:

> Anforderungen werden erst dann wirksam, wenn sie gemeinsam mit Qualitäts- und Akzetanzkriterien in überprüfbare technische Eigenschaften übersetzt und durch Evidenz gestützt werden.

## Status

`rtp-bff` wird iterativ weiterentwickelt. Der aktuelle Stand ist ein funktionsfähiger Prototyp mit serverseitiger OIDC-Session, Redis-Persistenz, Identitätsprojektion, kontrolliertem Token-Refresh und einer expliziten Proxy-Policy.

Weitere Inkremente werden insbesondere die sichere Bereitstellung autorisierter Rock-the-Prototype-Artefakte sowie die Trennung von Identität, Fähigkeiten, Nachweisen und Berechtigungen vertiefen.

---

**Rock the Prototype** — gemeinsam Herausforderungen verstehen, relevante Wertbeiträge ermöglichen und positive Wirkung leicht nachvollziehbar machen.
