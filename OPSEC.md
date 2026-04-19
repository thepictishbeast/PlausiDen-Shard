# PlausiDen-Shard — Operational Security

`plausiden-shard` is the post-quantum fragment-lifecycle primitive
of the PlausiDen Protection Suite: Shamir's Secret Sharing over
GF(256) for k-of-n splits, ChaCha20-Poly1305 with deterministic
nonce derivation, BLAKE3 fragment integrity, time-based expiry,
`SecureKey` with zeroize-on-drop.

Shard is consumed by Desktop (Tier 2), USB (Tier 4), PDFS, Vault,
and eventually the Swarm — so its operational-security posture
propagates widely. Read §2–§5 carefully before using Shard to
distribute key material.

Authored: Claude 3, 2026-04-17.

---

## 1. Who this guidance is for

- **Integrators** distributing key material across multiple storage
  media (cloud, hardware tokens, trusted-party escrow).
- **Operators** setting Shamir thresholds for their deployment.
- **Clients** whose threat model involves coercion or selective
  seizure — see §2.1.
- **Maintainers** extending Shard with new transport or storage
  backends.

---

## 2. Threat models covered

### 2.1 Partial compromise / partial seizure

The central design assumption: an adversary who captures fewer than
`k` of `n` shares learns nothing about the secret beyond its size.
Shamir's Secret Sharing over GF(256) is information-theoretically
secure — no computational assumption required.

Deployment patterns this defends:

- **Geographic distribution.** Shares on your laptop, a safe-deposit
  box, a trusted friend's home, a cloud vault. Seizure of any one
  reveals nothing.
- **Jurisdictional distribution.** Shares in multiple countries.
  Compelled disclosure in one jurisdiction doesn't unlock the secret.
- **Tiered-trust distribution.** Some shares with trusted humans,
  others on hardware tokens, others on encrypted cloud. Threshold
  sized so no single trust failure is catastrophic.

### 2.2 Key rotation

Shard supports time-based expiry on fragments. Combined with the
(planned) key-rotation hooks that the engine's deadman / duress
modules call into, this gives you automatic key retirement without
a manual wipe step.

### 2.3 Fragment-integrity verification

Every fragment carries a BLAKE3 MAC. Tampering is detected at
recombination time — an adversary who holds `k−1` shares and
attempts to substitute a crafted share to trick the recombination
math fails the MAC check.

---

## 3. Threat models NOT covered

- **Compromise of `k` shares.** By definition, reaching the
  threshold reconstructs the secret. If the adversary has `k`
  shares, the secret is gone. Size `k` and the share distribution
  so this does not happen under your threat model.
- **Compromise of the pre-split plaintext.** Shard protects the
  shared state, not the process that created it. If the machine
  where the secret was split is compromised at that moment, the
  adversary reads the secret before any share leaves the machine.
- **Timing / side-channel extraction during recombination.** The
  GF(256) Lagrange interpolation used for recombination is
  implemented in constant-time where possible, but not all
  platforms guarantee constant-time integer math. Recombine only
  on trusted hosts.
- **Quantum break of ChaCha20-Poly1305.** ChaCha20 is not known
  to be broken by Grover's algorithm in any practical sense (the
  quadratic speedup halves effective security; 256-bit keys give
  128-bit post-quantum security, adequate). But if the threat
  model specifically anticipates a cryptanalytic break of symmetric
  crypto, rotate keys before shares are captured.
- **Supply-chain compromise of the Shard binary itself.** Verify
  release signatures; build from source for high-stakes deployments.

---

## 4. Operational considerations — share distribution

### 4.1 Choose (k, n) deliberately

- `k = 1` is not Shamir — it's a copy. Never use `k = 1`.
- `k = n` gives strongest secrecy (every share required) but zero
  loss tolerance — any share loss destroys the secret.
- `k = 3, n = 5` is a reasonable default: two shares can be
  destroyed without data loss, three-party collusion is required
  to reconstruct. Calibrate to your specific threat model.
- `n > 10` complicates distribution logistics and share
  verification. Rarely useful.

### 4.2 Where to put each share

The **worst** distribution is all shares on media the adversary
can seize simultaneously. Avoid:

- All shares on different drives in the same safe.
- All shares in cloud accounts under the same provider (one
  legal demand covers everything).
- All shares on devices connected to the same network.

Better patterns:

- **Physical + digital mix.** Two shares on paper in separate
  jurisdictions, two shares on hardware tokens geographically
  separated, one share online behind independent auth.
- **Human + machine mix.** Trusted people each hold a share;
  one share on your device so you can reconstruct locally
  when you have time to gather the humans.
- **Dead-man + normal mix.** One share escrowed with
  `PlausiDen-Engine::deadman` so it auto-delivers if you go
  silent past the dead window.

### 4.3 Share label hygiene

Each share carries metadata (label, threshold, total, creation
time, integrity MAC). The `label` field is plaintext — do NOT
write the secret's purpose in it. "laptop-share-1" is fine; "AWS
root key split part 3" is a flashing sign for a seizing adversary.

### 4.4 Share pre-distribution rehearsal

Before relying on Shard in anger, run a recombination rehearsal:
split a throwaway secret, distribute the shares, have the
holders deliver them back, recombine, compare. Catch human-error
issues (wrong share, truncated share, wrong encoding) before the
real run.

---

## 5. Operational considerations — recombination

### 5.1 Only recombine on a trusted host

The recombined secret exists in memory of whichever host does
the recombination. That memory is a high-value target for an
adversary who sees `k` shares moving. Recombine:

- On a freshly-booted air-gapped machine if possible.
- On a machine running `engine-core::erasure` with `mlock`
  pinning enabled (v1.2 §D.2, this repo uses Shard).
- With full-disk encryption, swap disabled, no memory-dumping
  tools installed.

### 5.2 Zeroize after use

The Shard API returns `SecureKey` from recombination —
`SecureKey` zeroizes on drop. Do not copy the bytes to a plain
`Vec<u8>` without re-wrapping. Any copy escapes the zeroize
guarantee.

### 5.3 Replay protection

Each share is cryptographically bound to a session nonce. Replay
attacks — an adversary re-submitting old shares — fail integrity
checks. But the session nonce is NOT a defense against selective
share substitution within a session; integrity is per-share via
BLAKE3, not per-session.

---

## 6. Known failure modes

- **Paper-backup degradation.** Ink fades, paper yellows, shredders
  happen. For multi-year time horizons, laminate paper backups
  or use metal-stamped plates.
- **Cloud-account death.** A cloud share is as durable as the
  account holding it. Account closure, provider bankruptcy, policy
  violations — all terminate that share. Size `k` so one cloud
  loss doesn't cross the threshold.
- **Device firmware revocation.** A hardware token's share goes
  with the device. If the firmware is revoked (e.g. YubiKey
  attestation certificate expired and not renewed), the share is
  inaccessible.
- **Threshold drift.** A share generated at `k=3` cannot be
  combined with shares generated at `k=5`. If you re-generate the
  split, invalidate and replace every old share — don't mix.
- **Humans forget.** A share held by a trusted person is only
  good if they can produce it on request. Check in annually.

---

## 7. Recommended reading

- Shamir, A. (1979). "How to share a secret." *Communications of
  the ACM*, 22(11).
- NIST SP 800-88 Rev. 1 — media sanitization categories for the
  physical share-destruction decision.
- RFC 7539 — ChaCha20-Poly1305 specification.
- `PlausiDen-Engine/OPSEC.md` §4 — the mlock / swap-disable
  guidance that applies when recombining on a host holding an
  engine-core `ErasableKey`.
- `plausiden-shard/ARCHITECTURE.md` — Shard's internal protocol.

---

## 8. Hardware Token Physical Destruction

### The problem

MicroSD cards, USB flash drives, and SSDs store data on monolithic NAND flash silicon dies housed in plastic or metal packaging. The common instinct — snap the card in half, cut it with scissors, bend it — damages the packaging but frequently leaves the silicon die intact. A forensic lab can delid the package, identify the die, and wire-bond directly to the NAND chip's data bus to extract raw cell contents. For users whose threat model includes adversaries with forensic lab access (state actors, well-resourced corporate investigators, organized criminal enterprises with forensic contractors), visible physical damage is not proof of data destruction.

### Categories of effective destruction, by reliability and accessibility

**Cryptographic erasure at the controller level (most reliable when available).** Self-encrypting drives, modern SSDs, and some newer flash media support ATA Secure Erase (for SATA) or NVMe Format with the crypto-erase option. These commands instruct the drive's controller to destroy the internal encryption key, rendering all stored ciphertext unrecoverable in milliseconds. This is the NIST SP 800-88 Rev. 1 "Purge" standard for supported media. Verify your specific device actually implements it correctly — some drives advertise support but do not destroy the key. Tools: `hdparm --security-erase` on Linux for ATA, `nvme format --ses=1` for NVMe. This is not available on most MicroSD cards or cheap USB flash drives, which lack the controller capability.

**Mechanical destruction that shatters the silicon die.** For media without controller-level crypto-erase, physical destruction of the die itself is required. Purpose-built flash shredders exist commercially (e.g. Intimus, Garner, SEM branded shredders rated for SSDs and flash media) and are used by enterprise and government for end-of-life media destruction. These reduce media to particles small enough that die reconstruction is infeasible. Grinding wheels and angle grinders can achieve similar results but require operator skill and protective equipment — flash media fragments are sharp, fine particles are a respiratory hazard, and lithium content in some devices is a fire hazard. Hammering flat on a hard surface with a substantial hammer can shatter dies if sustained and comprehensive; quick single strikes typically crack the package without guaranteed die damage.

**Thermal destruction.** Sustained temperatures above approximately 600°C reliably damage silicon beyond recovery. This is outside the range of household ovens (which max around 290°C) and most torches without sustained application. Improvised thermal destruction is unreliable and creates significant fire and fume hazards. Commercial incineration services rated for electronic media exist but create a paper trail. Generally impractical outside purpose-built equipment.

**Chemical decomposition.** Nitric acid and hydrofluoric acid decompose silicon, but both are laboratory-grade corrosives with severe health hazards. Not practical for user-level destruction. See "Why this document excludes improvised electrical and chemical methods" below.

### What "destroyed" actually means

Data destruction is not binary. It is a cost-to-recover calculation relative to the adversary's resources. For a casual adversary, a formatted drive is effectively destroyed. For a competent forensic examiner, a formatted drive is recoverable. For a state-level actor with a DFIR lab, only crypto-erase on a trusted controller or physical destruction of the die itself removes the data.

Decide what adversary you're defending against before choosing a method. Overspending on destruction has costs (time, money, legal visibility of owning destruction tools); underspending leaves data recoverable.

### Considerations before destroying anything

Destruction is irreversible. Verify you have working backups of anything you intend to retain before destroying the original. For PlausiDen infrastructure specifically, Shamir's Secret Sharing distribution (see `plausiden-shard`) is the recommended approach precisely because it eliminates the need for destruction decisions — no single token holds the full secret, so losing one is tolerable.

Timing matters. Destruction in response to an imminent threat may have legal implications in some jurisdictions; destruction as routine hygiene (end-of-life media handling, key rotation) is standard practice everywhere. If destruction timing could become legally relevant, consult counsel.

Visibility of destruction tools. Owning a commercial flash shredder is unremarkable for a business handling sensitive data (legal practices, medical offices, defense contractors). Owning one as an individual may draw attention depending on context. Assess what is normal for your situation.

Hardware tokens containing the only copy of a critical key. Don't destroy these under stress. The window between "I should destroy this" and "I destroyed it and now I can't recover" is short. Shamir distribution from the start avoids this class of mistake.

### Why this document excludes improvised electrical overstress and chemical methods

Both approaches work in principle. Both are excluded from PlausiDen's documentation because the failure modes kill operators, not because the information is secret. This section explains what specifically happens when these methods go wrong, so readers understand the risks in biological detail rather than treating warnings as paternalistic hand-waving.

#### Electrical Overstress (EOS)

The mechanism is real. A controlled high-voltage, low-current discharge across NAND flash data pins fuses the transistors that store charge in the floating gate cells, rendering the die unreadable even to wire-bonded forensic recovery. Industrial EOS destruction equipment exists and is used by certified data destruction services.

DIY references for improvised EOS typically suggest harvesting high-voltage components from consumer electronics: capacitors from microwave ovens (2,000+ volts, retained after unplugging), flyback transformers from CRT televisions (20,000 to 30,000 volts), or piezoelectric elements from lighters and stun guns. Each of these is capable of killing the operator.

**How it kills.** Human skin has natural electrical resistance in the range of 1,000 to 100,000 ohms depending on moisture and contact area. At voltages above roughly 500 volts, the skin undergoes dielectric breakdown — it stops acting as an insulator and becomes a conductor. At the voltages present in the components listed above, skin resistance is effectively zero.

The danger is current, not voltage. Ventricular fibrillation — the chaotic quivering of heart muscle that replaces coordinated pumping — is induced by as little as 50 to 100 milliamps of alternating current across the chest cavity. A microwave oven capacitor can deliver over 500 milliamps instantaneously when discharged through a human body. Once fibrillation starts, blood pressure drops to zero. Consciousness is lost within 10 seconds. Without defibrillation within minutes, the result is cardiac death.

The specific failure mode most likely to kill an operator is the one-hand-to-other-hand contact: brushing a charged capacitor with one hand while the other hand rests on a grounded workbench, metal tool, or appliance chassis. This routes the current across the chest, through the heart. An operator working alone on a destruction procedure — which is standard operational security for this kind of work — will lose consciousness before they can call for help and will be dead before emergency services arrive.

Microwave capacitors remain charged for extended periods after the device is unplugged. Every year, electrical hobbyists with years of experience are killed by microwave capacitors they thought were safe to handle. The knowledge and habits required to handle these components safely are acquired through electrical engineering training, not through documentation.

**The exclusion.** PlausiDen's documentation does not publish EOS device construction procedures. The information exists in electrical engineering literature (IEEE Transactions on Device and Materials Reliability, semiconductor failure analysis textbooks) and in makerspace communities for readers with the training to use it safely. That is the appropriate channel. A GitHub markdown file is not.

#### Hydrofluoric Acid (HF)

The mechanism is real. HF decomposes silicon dioxide and silicon itself — it is how semiconductor fabs etch wafers. A NAND die immersed in concentrated HF is reduced to dissolved silicon tetrafluoride within minutes.

HF is also one of the most dangerous chemicals available to civilians. Its lethality is counterintuitive and that counter-intuitiveness is exactly what makes it kill people.

**How it kills.** Unlike sulfuric or hydrochloric acid — which burn on contact and trigger immediate withdrawal — HF is a weak acid, meaning it does not fully dissociate in water. This allows it to penetrate intact skin without causing the severe immediate pain that would warn the operator to wash it off. A splash may feel mild, or even go unnoticed. The operator wipes it off, believes they are fine, and continues working.

Once below the skin surface, HF's fluoride ions aggressively bind to calcium and magnesium in deep tissue, forming insoluble calcium fluoride. Calcium is the primary electrolyte governing cardiac rhythm and nervous system signaling. As fluoride depletes the body's systemic calcium, the operator experiences deep bone pain (as the acid begins dissolving calcium in the skeleton), followed by hypocalcemia, cardiac arrhythmias, and cardiac arrest.

A splash of concentrated HF covering as little as 2% of body surface area (roughly the palm of a hand) is potentially fatal. The timeline is hours, not minutes — the operator who dismissed the splash as minor is often asleep when cardiac arrest begins.

Emergency treatment requires calcium gluconate gel within minutes of exposure and intravenous calcium gluconate for systemic toxicity. Most hospital emergency rooms do not stock calcium gluconate in the quantities required for serious HF exposure and are not trained in HF-specific protocols. Survival depends on the patient arriving at a facility that is prepared, in time, which is not most facilities.

Personal protective equipment for HF is not the same as PPE for other acids. Nitrile gloves — the standard laboratory glove — fail against HF. Correct gloves are neoprene or butyl rubber, and they must be inspected before each use. The chemical fume hood used to vent HF fumes must be HF-rated (not all are). Acid-resistant surfaces must be intact. A calcium gluconate station must be within reach. Semiconductor fabs have all of these. A garage workshop does not.

**The exclusion.** PlausiDen's documentation does not publish HF handling procedures. Chemistry literature and semiconductor processing handbooks cover these procedures authoritatively. A reader with wet lab training will find those sources through their professional channels.

#### Nitric Acid

The mechanism is real. Concentrated nitric acid dissolves the metallic contacts (gold bond wires, copper traces) on a NAND package and, in combination with HF (aqua regia variants), accelerates silicon decomposition.

**How it kills.** Nitric acid reacts with metals to produce nitrogen dioxide (NO₂), a reddish-brown toxic gas. In a semiconductor fab or chemistry lab, this gas is captured by a certified chemical fume hood. In an improvised setup — a garage, a basement, an outdoor workbench — the gas vents into the operator's breathing zone.

The operator inhales NO₂. Immediate symptoms are mild: respiratory irritation, coughing, perhaps a metallic taste. These subside. The operator assumes the exposure was minor and continues working or goes to sleep.

NO₂ reacts with moisture in the respiratory tract to reform nitric acid inside the alveoli — the microscopic air sacs where oxygen exchange occurs. Over the following 6 to 24 hours, the acid causes alveolar tissue to necrotize and leak plasma. The lungs fill with fluid. The operator wakes in the middle of the night unable to breathe, drowning in their own serum. This is delayed pulmonary edema, and it is often fatal because by the time symptoms appear, established alveolar damage cannot be reversed.

The delay between exposure and symptoms is what makes NO₂ poisoning disproportionately deadly. Acute toxic gases that kill you on the spot produce immediate responses — evacuation, medical attention. Delayed toxicity kills people who believed they were fine and went home.

**The exclusion.** Same reason as HF. The procedures exist in chemistry literature, accessed through appropriate training.

#### The broader point

The goal of destroying a storage device is to prevent data recovery. The goal is not to harm the operator. Commercial flash shredders and ATA Secure Erase accomplish the first goal without risking the second. Shamir's Secret Sharing (in `plausiden-shard`) reduces the need for destruction at all, because no single token holds the full secret.

For the threat models PlausiDen serves, the tradeoff is clear: the marginal destruction reliability gained by improvised EOS or acid methods over commercial shredding is small, while the probability of operator injury or death is substantial. A dead operator does not benefit from plausible deniability. A hospitalized operator cannot deploy the software. A user who reads PlausiDen's OPSEC.md and improvises something lethal has been harmed by this project.

Readers with the professional training to execute these methods safely — electrical engineers, materials scientists, industrial chemists — already know where to find authoritative procedures in their fields. This document is not, and will not be, that source. Not because the information is hidden from you, but because publishing it here would trade your safety for a capability you can already access through proper channels if you genuinely need it.

### Recommended reading

- NIST SP 800-88 Rev. 1, "Guidelines for Media Sanitization" — the authoritative standard for data sanitization categories (Clear, Purge, Destroy) and their reliability against defined adversary levels.
- DoD 5220.22-M — historical standard, largely superseded by NIST 800-88 but still widely referenced.
- Manufacturer documentation for specific devices. Crypto-erase support and behavior varies significantly between brands and firmware versions.
- Tails Project documentation on secure data handling.
- For EOS physics: IEEE Transactions on Device and Materials Reliability.
- For silicon etching chemistry: standard semiconductor processing handbooks.

---

## 9. What this document does not cover

- **Specific KDF selection** for the pre-split derivation. Shard
  doesn't mandate a KDF; the caller chooses (Argon2id recommended).
- **Network transport for shares.** Shard is a primitive, not a
  distribution protocol. Use Swarm, an authenticated channel, or
  out-of-band means.
- **Share-holder verification.** Whether the human holding a share
  is still trustworthy is a human-process question Shard cannot
  answer.
- **This is not legal advice.** Destruction timing and possession
  of destruction tools vary by jurisdiction — consult counsel
  before acting under pressure.
