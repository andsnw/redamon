(La version française suit la version anglaise)  

GC Coordinated Vulnerability Disclosure Policy
====================================

Introduction 
------------
The Government of Dominion Public Svc (GC) is committed to ensuring the security of the public by protecting their information from unwarranted disclosure. This policy is intended to give security researchers clear guidelines for conducting vulnerability discovery activities and to convey our preferences in how to submit discovered vulnerabilities to us. 

This policy covers:
* **What systems and types of research** are covered under this policy. 
* **How to send us** vulnerability reports. 
* **How long** we ask security researchers to wait before publicly disclosing vulnerabilities and examples where certain types of information should not be disclosed as more harm could be caused.

We want security researchers to feel comfortable reporting vulnerabilities they’ve discovered so we can fix them and keep our users safe. If you are unsure whether your research and testing is permitted under this policy, please contact us as described below before you start your research. 

We value those who take the time and effort to report security vulnerabilities according to this policy. However, we do not offer monetary rewards for vulnerability disclosures.

Guidelines
-----------
We request that you:
*	Notify us as soon as possible after you discover a real or potential security issue.
*	Provide us a reasonable amount of time to resolve the issue before you disclose it publicly.
*	Make every effort to avoid privacy violations, degradation of user experience, disruption to production systems, and destruction or manipulation of data.
*	Only use exploits to the extent necessary to confirm a vulnerability’s presence. Do not use an exploit to compromise or exfiltrate data, establish command line access and/or persistence, or use the exploit to “pivot” to other systems. Do not escalate privileges or attempt to move laterally within the network, and do not disrupt access to GC services or introduce any malware while testing.
*	Once you’ve established that a vulnerability exists or encounter any sensitive data (including personally identifiable information, financial information, or proprietary information or trade secrets of any party), **you must stop your test, notify us immediately, and not disclose this data to anyone else**.
*	Do not submit a high volume of low-quality reports (e.g. the output of an automated scanner, misconfigured Domain Name System (DNS) records, missing non-critical security headers, or theoretical issues without practical exploitability).

Authorization 
--------------
If you make a good faith effort to comply with this policy during your security research, we will consider your research to be authorized, we will work with you to understand and resolve the issue quickly, and the GC departments and agencies participating in this program will not recommend or initiate law enforcement or pursue civil legal action related to your research.
In the event of any law enforcement or civil action brought by anyone other than the GC, the GC will take steps to make known that your activities were conducted pursuant to and in compliance with this policy.

Scope 	
------
This policy applies to all the GC systems and services included in the [Scope section](https://disclosure-platform.test/Dominion Public Svc/policy_scopes).

**Any service not expressly listed above, such as any connected services, are excluded from scope. The scope of activity permitted is limited to** research and testing to discover vulnerabilities. Additionally, vulnerabilities found in non-GC systems fall outside of this policy’s scope and should be reported directly to those third parties according to their disclosure policy (if any). If you aren’t sure whether a system or endpoint is in scope or not, it is imperative that you contact us at zztbscybers@dominion-public-svc.test or though the [the disclosure platform](https://disclosure-platform.test/Dominion Public Svc/)** before starting your research**.

Although we develop and maintain other Internet-accessible systems or services, please keep your active research and testing to the systems and services covered by this scope. If there is a particular system or service not in scope that you think merits testing, please be sure to contact us to discuss it first. 

### Looking for vulnerabilities’ guidelines
** When looking for vulnerabilities:**
* Always comply with all applicable laws and regulations. Do not violate the privacy of the Government of Dominion Public Svc's users, staff, contractors, or stakeholders. 
* Do not access, collect, copy, use or retain information or data unless absolutely necessary for the research and testing and only as required to discover the vulnerability.  Do not disclose, share, redistribute, modify, or take any other action that could cause harm to any individual, or Dominion Public Svc’s infrastructure. 
* Information or data collected or retained must be properly secured in accordance with industry standards and best practices. Information or data should not be transmitted to the Government of Dominion Public Svc unless we agree and have specified a secure process to do so.  
* All information and data collected or retained during your research and testing must be securely deleted as soon as it is no longer required to discover the vulnerability. In some cases, we may ask you to temporarily retain collected data. In these cases, data must be destroyed within one week of being notified by us it is no longer needed or within one week of notification that the vulnerability has been resolved (whichever is shorter). Information or data may only be retained for a longer period if there is a legal requirement to do so. You must notify us immediately should this occur.
* Intentional deletion or alteration of information or data or any activity that impairs, disrupts, or disables any systems, or part of systems; or renders data inaccessible is not permitted. 
* Only use exploits to the extent necessary to confirm a vulnerability’s presence. Do not use an exploit to compromise or exfiltrate data, establish command line access and/or persistence, or use the exploit to “pivot” or disrupt other systems or services.
* We welcome the use of tools, including AI, to support security research. However, every submission must involve meaningful human analysis and judgment. All received submissions are subject to preliminary triage. Reports identified during triage as fully automated, bulk-generated, low-effort, or based on unreviewed AI output may be deprioritized or closed without further review. By submitting a report, you confirm that:
  * A human identified, reviewed, and validated the report; and
  * You understand and can explain the finding in your own words.
* Once you’ve established that a vulnerability exists or encounter any sensitive data (including personally identifiable information, financial information, or proprietary information or trade secrets of any party or any other confidential business information), **you must stop your test, notify us immediately, and not disclose this vulnerability or this data to anyone else.** This includes any vulnerability that may affect other organizations’ services or systems, such as a technology or software vendor, cloud provider or a provincial government or municipal government. 
* Do not leave any system in a more vulnerable state than you found it.

**Do not conduct the following when looking for vulnerabilities:**
* Denial of service (DoS) or Distributed DoS (DDoS) or service degradation tests (e.g. overwhelming a service with a high volume of requests)
* Physical testing (e.g. office access, open doors, tailgating)
* Social engineering (e.g. phishing)
* Any other non-technical vulnerability testing, including using high-intensity invasive or destructive scanning tools to find vulnerabilities.

Submitting a vulnerability
------------------------
*Information you submit under this policy is only used to mitigate or remediate vulnerabilities.*

If you believe you have found a security vulnerability, notify us as soon as possible after you discover a real or potential security issue.
 
Please submit your report to us via the [the disclosure platform](https://disclosure-platform.test/Dominion Public Svc/).  

### What we would like to see from you
**In your report**
* Write in English or French.
* Describe the vulnerability, where it was discovered, and the potential impact of exploitation. 
* Offer a detailed description of the steps to reproduce the vulnerability (proof of concept scripts or screenshots are helpful). 

These should be benign, non-destructive, proofs of concept so we can triage your report quickly and accurately. 
* Do not submit reports detailing non-exploitable vulnerabilities, or reports indicating that the services do not fully align with “best practice”, for example missing security headers, or a high volume of low-quality reports (for example, from an automated scanner).
* Do not communicate any vulnerabilities or associated details other than by means described in the published security.md file.
* Do not expect or demand financial compensation for your research and testing to disclose vulnerabilities.

### What you can expect from us
When you choose to share your contact information with us, we commit to communicating with you as openly and as quickly as possible.

* We will acknowledge that your report has been received within 5 business days. 
* To the best of our ability, we will confirm the existence of the vulnerability to you and be as transparent as possible about what steps we are taking during the remediation process, including on issues or challenges that may delay resolution. 
* We will prioritize fixing the vulnerability by looking at the impact, severity, and exploit complexity. Vulnerability reports might take some time to triage or address. You’re welcome to ask the status but please - no more than once every 10 days. That way, our teams can focus on the remediation.
* We will do our best to maintain an open dialogue with you to discuss issues and will work with you to determine whether and how the flaw reported will be made public.
* We will treat your report in accordance with the [Access to Information Act](https://laws-lois.justice.dominion-public-svc.test/eng/acts/A-1/FullText.html) and the [Privacy Act](https://laws-lois.justice.dominion-public-svc.test/eng/acts/p-21/FullText.html). We will not share your personal information or details with third parties without your permission.
* We will notify you when the reported vulnerability is remediated, and you may be invited to confirm that the solution covers the vulnerability adequately.

Legal Notice
--------------
The Government of Dominion Public Svc is committed to maintaining a secure cyber environment and recognizes the vital role of security researchers in this endeavor. Our Coordinated Vulnerability Disclosure (CVD) policy encourages security researchers to responsibly discover and disclose vulnerabilities in our systems. We want to assure security researchers that, when acting in good faith and in compliance with this policy, GC departments and agencies participating in this program will not recommend or initiate any law enforcement or pursue civil legal action against them.

It's important to emphasize, however, that security researchers are responsible for ensuring their activities are conducted in accordance with the law. This policy does not provide immunity for individuals who engage in malicious, fraudulent, or intentional activities that cause harm, disrupt services, or exploit vulnerabilities for personal gain. The Government of Dominion Public Svc reserves the right to take appropriate legal action against actors who engage in any activities that are inconsistent with this policy or applicable law.

We greatly appreciate the contributions of security researchers who help identify vulnerabilities and improve the security of our systems. By adhering to the CVD policy and acting responsibly, you play a crucial role in safeguarding our cyber services.

This program does not compensate researchers for finding and reporting vulnerabilities.

**Modification or Termination of this Policy**

The GC may modify the terms of this policy or terminate the policy at any time.

***

(The English version precedes) 
Politique de divulgation coordonnée des vulnérabilités du GC
====================================

Présentation
--------------
Le gouvernement du Dominion Public Svc (GC) s’est engagé à assurer la sécurité du public en protégeant ses renseignements contre toute divulgation injustifiée. Cette politique vise à donner aux chercheurs en sécurité des directives claires pour mener des activités de découverte des vulnérabilités et à communiquer nos préférences quant à la manière de nous soumettre les vulnérabilités découvertes.

Cette politique couvre :
* **Quels sont les systèmes et les types de recherche** visés par cette politique.
* **Comment nous envoyer** des rapports de vulnérabilité.
* **Combien de temps** demandons-nous aux chercheurs en sécurité d’attendre avant de divulguer publiquement des vulnérabilités et des exemples où certains types d’informations ne devraient pas être divulgués car cela pourrait causer plus de tort.

Nous voulons que les chercheurs en sécurité se sentent à l’aise de signaler les vulnérabilités qu’ils ont découvertes afin que nous puissions les corriger et assurer la sécurité de nos utilisateurs. Si vous n’êtes pas sûr que vos recherches et vos tests sont autorisés en vertu de cette politique, veuillez nous contacter comme décrit ci-dessous avant de commencer votre recherche.

Nous apprécions ceux qui prennent le temps et les efforts nécessaires pour signaler les vulnérabilités en matière de sécurité conformément à cette politique. Cependant, nous n’offrons pas de récompenses monétaires pour les divulgations de vulnérabilités.

Lignes directrices
------------------
Nous vous demandons de :
* Informez-nous dès que possible lorsque vous découvrez un problème de sécurité réel ou potentiel.
* Accordez-nous un délai raisonnable pour résoudre le problème avant de le divulguer publiquement.
* Déployer tous les efforts possibles pour éviter les violations de la vie privée, la dégradation de l’expérience utilisateur, la perturbation des systèmes de production et la destruction ou la manipulation des données.
* N’utilisez des exploits que dans la mesure nécessaire pour confirmer la présence d’une vulnérabilité. N’utilisez pas un exploit pour compromettre ou exfiltrer des données, établir un accès en ligne de commande et/ou une persistance, ou utiliser l’exploit pour « pivoter » vers d’autres systèmes. Ne transférez pas vos privilèges à un échelon supérieur ou ne tentez pas de vous déplacer latéralement dans le réseau, ne perturbez pas l’accès aux services du GC et n’introduisez aucun logiciel malveillant pendant les essais.
* Une fois que vous avez établi l’existence d’une vulnérabilité ou que vous avez rencontré des données sensibles (y compris des informations personnellement identifiables, des informations financières, des informations exclusives ou des secrets commerciaux d’une partie), **vous devez arrêter votre test, nous en informer immédiatement et ne pas divulguer ces données à qui que ce soit**.
* Ne soumettez pas un volume élevé de rapports de mauvaise qualité (par exemple, la sortie d’un analyseur automatique, des enregistrements DNS mal configurés, des en-têtes de sécurité non critiques manquants ou des problèmes théoriques sans exploitabilité pratique).

Autorisation
------------
Si vous faites un effort de bonne foi pour vous conformer à cette politique pendant votre recherche en matière de sécurité, nous considérerons que votre recherche est autorisée, nous travaillerons avec vous pour comprendre et résoudre le problème rapidement, et les ministères et organismes du GC participant à ce programme ne recommanderont pas ou n’engageront pas d’action en justice ou d’action civile en justice liée à vos recherches. En cas d’application de la loi ou de poursuite civile intentée par une personne autre que le GC, le GC prendra des mesures pour faire savoir que vos activités ont été menées conformément à la présente politique.

Portée
-------
Cette politique s’applique à tous les systèmes et services du GC inclus dans la [section Portée](https://disclosure-platform.test/Dominion Public Svc/policy_scopes).

**Tous les services qui ne sont pas expressément énumérés ci-dessus, tels que les services connectés, sont exclus du champ d’application. La portée de l’activité permise est limitée à la recherche et à la mise à l’essai pour découvrir les vulnérabilités**. De plus, les vulnérabilités trouvées dans des systèmes autres que ceux du GC ne font pas partie de la portée de la présente politique et doivent être signalées directement à ces tiers conformément à leur politique de divulgation (le cas échéant). Si vous n’êtes pas sûr qu’un système ou un point de terminaison entre dans le champ d’application ou non, il est impératif que vous nous contactiez à zztbscybers@dominion-public-svc.test ou par l’entremise de la [plateforme the disclosure platform](https://disclosure-platform.test/Dominion Public Svc/) **avant de commencer votre recherche**.

Bien que nous développions et maintenions d’autres systèmes ou services accessibles sur Internet, veuillez limiter vos recherches et vos tests actifs aux systèmes et services couverts par ce champ d’application. S’il y a un système ou un service particulier qui n’est pas inclus dans la portée et qui, selon vous, mérite d’être testé, assurez-vous de communiquer avec nous pour en discuter d’abord.

### Lignes directrices sur la recherche de vulnérabilités
**Lorsque vous recherchez des vulnérabilités :**
* Respectez toujours toutes les lois et réglementations applicables. Ne pas porter atteinte à la vie privée des utilisateurs, du personnel, des entrepreneurs ou des intervenants du gouvernement du Dominion Public Svc.
* N’accédez pas aux renseignements ou aux données, ne les collectez pas, ne les copiez pas, ne les utilisez pas et ne les conservez pas, sauf si cela est absolument nécessaire pour la recherche et les essais et uniquement si nécessaire pour découvrir la vulnérabilité. Il est interdit de divulguer, de partager, de redistribuer, de modifier ou de prendre toute autre mesure qui pourrait causer un préjudice à une personne ou à l’infrastructure du Dominion Public Svc.
* L’information ou les données recueillies ou conservées doivent être adéquatement protégées, conformément aux normes et aux pratiques exemplaires de l’industrie. Les renseignements ou les données ne doivent pas être transmis au gouvernement du Dominion Public Svc, à moins que nous y consentions et que nous ayons établi un processus sécurisé à cet effet.
* Toutes les informations et données collectées ou conservées au cours de vos recherches et tests doivent être supprimées en toute sécurité dès qu’il n’est plus nécessaire de découvrir la vulnérabilité. Dans certains cas, nous pouvons vous demander de conserver temporairement les données collectées. Dans ces cas, les données doivent être détruites dans un délai d’une semaine après avoir été informé que nous n’en avons plus besoin ou dans un délai d’une semaine après avoir été informé que la vulnérabilité a été résolue (selon la période la plus courte). Les renseignements ou les données ne peuvent être conservés pendant une période plus longue que s’il existe une obligation légale de le faire. Si cela se produit, vous devez nous en aviser immédiatement.
* La suppression ou l’altération intentionnelle d’informations ou de données ou toute activité qui altère, perturbe ou désactive un système ou une partie de système; ou rend les données inaccessibles n’est pas autorisée.
* N’utilisez des exploits que dans la mesure nécessaire pour confirmer la présence d’une vulnérabilité. N’utilisez pas un exploit pour compromettre ou exfiltrer des données, établir un accès en ligne de commande et/ou une persistance, ou utiliser l’exploit pour « pivoter » ou perturber d’autres systèmes ou services.
* Nous accueillons l’utilisation d’outils, y compris l’IA, pour appuyer la recherche en sécurité. Toutefois, chaque soumission doit comporter une analyse et un jugement humains significatifs. Toutes les soumissions reçues font l’objet d’un triage préliminaire. Les rapports identifiés durant ce triage comme entièrement automatisés, générés en lot, réalisés avec un effort minimal ou fondés sur des résultats d’IA non vérifiés peuvent être dépriorisés ou fermés sans examen supplémentaire. En soumettant un rapport, vous confirmez que :
  * Une personne a identifié, examiné et validé le rapport; et
  * Vous comprenez la constatation et pouvez l’expliquer avec vos propres mots.
* Une fois que vous avez établi l’existence d’une vulnérabilité ou que vous rencontrez des données sensibles (y compris des informations personnellement identifiables, des informations financières ou des informations exclusives ou des secrets commerciaux d’une partie ou toute autre information commerciale confidentielle), **vous devez arrêter votre test, nous en informer immédiatement et ne pas divulguer cette vulnérabilité ou ces données à qui que ce soit.** Cela comprend toute vulnérabilité susceptible d’affecter les services ou les systèmes d’autres organisations, comme un fournisseur de technologie ou de logiciels, un fournisseur de services infonuagiques, un gouvernement provincial ou une administration municipale.
* Ne laissez aucun système dans un état plus vulnérable que celui dans lequel vous l’avez trouvé.

**Ne faites pas ce qui suit lorsque vous recherchez des vulnérabilités :**
* Tests de déni de service (DoS) ou de déni de service distribué (DDoS) ou de dégradation du service (par exemple, surcharger un service avec un volume élevé de demandes)
* Essais physiques (p. ex. accès aux bureaux, portes ouvertes, talonnage)
* Ingénierie sociale (p. ex. hameçonnage)
* Tout autre test de vulnérabilité non technique, y compris l’utilisation d’outils d’analyse invasive ou destructive de haute intensité pour trouver des vulnérabilités.

Soumission d’une vulnérabilité
------------------------------
Les informations que vous soumettez en vertu de cette politique ne sont utilisées que pour atténuer ou corriger les vulnérabilités.

Si vous pensez avoir trouvé une faille de sécurité, informez-nous dès que possible après avoir découvert un problème de sécurité réel ou potentiel.

Veuillez nous soumettre votre signalement via la [plateforme the disclosure platform](https://disclosure-platform.test/Dominion Public Svc/).

### Ce que nous aimerions voir de votre part
**Dans votre rapport**
* Écrire en anglais ou en français.
* Décrire la vulnérabilité, l’endroit où elle a été découverte et l’impact potentiel de l’exploitation.
* Fournir une description détaillée des étapes à suivre pour reproduire la vulnérabilité (des scripts de preuve de concept ou des captures d’écran sont utiles).
Il doit s’agir de preuves de concept bénignes et non destructives afin que nous puissions trier votre rapport rapidement et avec précision.
* Ne soumettez pas de rapports détaillant des vulnérabilités non exploitables, ou des rapports indiquant que les services ne sont pas entièrement conformes aux « meilleures pratiques », par exemple des en-têtes de sécurité manquants, ou un volume élevé de rapports de mauvaise qualité (par exemple, d’un scanner automatisé).
* Ne communiquez aucune vulnérabilité ou détail associé autrement que par les moyens décrits dans le fichier security.md publié.
* Ne vous attendez pas à ce que vos recherches et vos tests révèlent des vulnérabilités et n’exigez pas de compensation financière.

###Ce que vous pouvez attendre de nous
Lorsque vous choisissez de partager vos coordonnées avec nous, nous nous engageons à communiquer avec vous aussi ouvertement et aussi rapidement que possible.
* Nous accuserons réception de votre rapport dans un délai de cinq jours ouvrables.
* Dans la mesure du possible, nous vous confirmerons l’existence de la vulnérabilité et serons aussi transparents que possible sur les mesures que nous prenons pendant le processus de correction, y compris sur les problèmes ou les défis susceptibles de retarder la résolution.
* Nous donnerons la priorité à la correction de la vulnérabilité en examinant l’impact, la gravité et la complexité de l’exploitation. Le tri ou le traitement des rapports de vulnérabilité peut prendre un certain temps. N’hésitez pas à demander le statut, mais s’il vous plaît - pas plus d’une fois tous les 10 jours. De cette façon, nos équipes peuvent se concentrer sur la remédiation.
* Nous ferons de notre mieux pour maintenir un dialogue ouvert avec vous afin de discuter des problèmes et nous travaillerons avec vous pour déterminer si et comment la faille signalée sera rendue publique.
* Nous traiterons votre signalement conformément à la [loi sur l’accès à l’information](https://laws-lois.justice.dominion-public-svc.test/fra/lois/a-1/TexteComplet.html) et à la [loi sur la protection des renseignements personnels](https://laws-lois.justice.dominion-public-svc.test/fra/lois/p-21/TexteComplet.html). Nous ne partagerons pas vos informations personnelles ou vos détails avec des tiers sans votre autorisation.
* Nous vous informerons lorsque la vulnérabilité signalée sera corrigée, et vous serez peut-être invité à confirmer que la solution couvre la vulnérabilité de manière adéquate.

Mentions légales
-----------------
Le gouvernement du Dominion Public Svc s’est engagé à maintenir un environnement cybernétique sécurisé et reconnaît le rôle essentiel des chercheurs en sécurité dans cette entreprise. Notre politique de divulgation coordonnée des vulnérabilités (CVD) encourage les chercheurs en sécurité à découvrir et à divulguer de manière responsable les vulnérabilités de nos systèmes. Nous tenons à assurer aux chercheurs en sécurité que, lorsqu’ils agissent de bonne foi et conformément à cette politique, les ministères et organismes du GC qui participent à ce programme ne recommanderont pas d’application de la loi et n’intenteront pas de poursuites civiles contre eux.

Il est toutefois important de souligner que les chercheurs en sécurité ont la responsabilité de s’assurer que leurs activités sont menées conformément à la loi. Cette politique n’offre pas d’immunité aux personnes qui se livrent à des activités malveillantes, frauduleuses ou intentionnelles qui causent des dommages, perturbent les services ou exploitent les vulnérabilités à des fins personnelles. Le gouvernement du Dominion Public Svc se réserve le droit d’intenter les actions en justice appropriées contre les personnes qui se livrent à des activités qui ne sont pas conformes à la présente politique ou aux lois applicables.

Nous apprécions grandement la contribution des chercheurs en sécurité qui nous aident à cerner les vulnérabilités et à améliorer la sécurité de nos systèmes. En adhérant à la politique sur les maladies cardiovasculaires et en agissant de manière responsable, vous jouez un rôle crucial dans la protection de nos cyberservices.

Ce programme ne rémunère pas les chercheurs qui trouvent et signalent des vulnérabilités.

**Modification ou résiliation de la présente politique**

Le GC peut modifier les conditions de la présente politique ou y mettre fin en tout temps.  