# Vault — estado técnico actual

Vault se está construyendo como infraestructura financiera crítica. El proyecto
no usa “privacidad” como una etiqueta comercial: cada propiedad deberá estar
definida contra adversarios concretos, cubierta por pruebas y revisada por
especialistas externos.

Desde el 21 de agosto de 2026, todo trabajo nuevo debe apuntar a la arquitectura
desplegable: no se aceptan MVP desechables, rutas de demostración ni garantías
de seguridad simplificadas como entregables. La intención de producción no
significa que el estado actual sea seguro; cada componente debe superar las
especificaciones, pruebas adversariales, benchmarks, builds reproducibles,
revisión independiente y auditorías establecidas en el
[`estándar de producción`](PRODUCTION_STANDARD.md).

## Implementado

- Modelo contable transparente con oferta máxima y quema del 0,5%.
- Notas consumibles y rechazo de doble gasto.
- Pruebas generativas de secuencias aleatorias de transferencias.
- Tipos separados para chain ID, circuit ID, raíces, compromisos y nullifiers.
- Ventana de raíces recientes para pruebas de pertenencia.
- Rechazo de replay entre redes y circuitos.
- Límites previos a la verificación para evitar ataques de memoria/CPU.
- Digest determinista que vincula ciphertexts, gas, burn commitment y outputs.
- Derivación de claves separada por red y cuenta, con direcciones diversificadas
  externas e internas.
- Capacidades separadas para gastar, visualizar entradas y recuperar salidas.
- Autorización RedPallas con una clave de validación aleatorizada nueva por cada
  gasto y firma vinculada a la red y a los efectos de la transacción.
- Notas VLT con compromisos Sinsemilla, nullifiers Orchard, compromisos de valor
  ocultos y cifrado autenticado de tamaño fijo.
- Recuperación de la misma nota por receptor y emisor, con rechazo de claves,
  ciphertexts, commitments, `rho` y ephemeral keys alterados.
- Árbol Sinsemilla de profundidad 32 con roots deterministas, snapshots
  restaurables y verificación nativa de paths de pertenencia.
- Escaneo local por lotes y con límites para múltiples viewing keys.
- Interfaz de verificador que falla cerrada; no existe un “aceptar todo” en el
  binario de producción.
- CI reproducible para formato, pruebas, Clippy, documentación y MSRV.
- Guest RISC Zero 3.0.6 que generó y verificó una prueba ZK real de
  contabilidad con importes ocultos y modo de desarrollo deshabilitado.
- Adaptador que verifica el recibo contra el image ID fijado y lo aplica a la
  misma máquina de estado H1.
- Codec canónico transfer-v2 con acciones Ironwood/Orchard emparejadas y padding público
  en clases de 2, 4, 8 o 16 acciones.
- Firmas RedPallas por acción vinculadas a todos los efectos, ciphertexts de
  tamaño fijo y rechazo de truncamientos, orden alternativo y bytes sobrantes.
- Transición transfer-v2 atómica que registra nullifiers y deriva internamente
  la nueva root del árbol solamente después de validar la prueba.
- Notas y cifrado migrados a Ironwood V3, con el circuito Halo2 endurecido
  `PostNu6_3` y fingerprint exacto de su verifying key.
- Prueba Halo2 real de dos acciones (7.264 bytes) para propiedad, pertenencia
  Merkle, nullifier, `rk`, apertura de notas, `rho` y compromiso neto; rechaza
  cambios de anchor, transcript y longitud.
- Envelope compuesto fail-closed: la prueba de acciones no puede llegar a
  consenso sin un segundo verificador de contabilidad, gas, burn y ciphertext.
- Burn cifrado Pallas ElGamal de 64 bytes que ya cifra, agrega, filtra shares
  DLEQ hostiles y recupera el total dentro de un límite explícito. H1-C4 exige
  128 efectos y 16 ventanas, sin revelar por timeout; DKG, integración H2 y el
  benchmark del límite completo siguen bloqueando uso real.
- Componente Halo2 de contabilidad para los buckets 2/4/8/16: descompone cada
  importe en 64 bits, fuerza booleanos y dummy slots vacíos, acumula importes,
  vincula gas público, calcula `ceil(taxable/200)` con resto menor que 200 y
  exige conservación exacta. H1-C3 fija IDs y vectores de conformidad para
  todos los buckets, pero no existe un verificador de consenso activado.
- La celda exacta de burn calculada por esa aritmética ya abre el compromiso de
  valor y satisface dentro del mismo circuito `C1=[r]G` y
  `C2=[burn]H+[r]PK_epoch`; alterar el burn o el ciphertext falla.
- Prueba Halo2 real de esa capa combinada: 5.504 bytes, 10,154 segundos de
  proving y 98 ms de verificación en una medición release local; transcript o
  instancia alterados son rechazados. Su VK aún no se congela.
- Fork local fijado y documentado de Orchard 0.15.5, basado exactamente en el
  commit upstream `29d1d55db62153dcaeef8ef631c8991c53ed1248`. El diff de código
  fuente está limitado a la API de composición del circuito Action.
- Primer `VaultTransferCircuit` monolítico: las mismas celdas privadas
  `v_old`/`v_new` que abren las notas Action alimentan directamente la
  contabilidad; ya no existen dos copias independientes de esos importes.
- La exención de burn permanece privada y solo satisface el circuito cuando
  las cuatro coordenadas del receptor expandido de salida coinciden con las de
  la nota consumida. Una salida propia aún puede declararse gravable, lo que
  únicamente sobrepaga; una salida externa no puede declararse cambio.
- Prueba Halo2 real del primer circuito monolítico: 9.504 bytes, 25,842 s de
  proving y 151 ms de verificación, después de 33,769 s de keygen provisional
  en una medición release local. Alterar el transcript o una instancia falla.
- Pruebas adversariales rechazan valores contables redistribuidos que conservan
  correctamente en la capa aislada y una salida externa presentada como cambio
  sin impuesto.
- El marcador privado dummy ya se deriva dentro del circuito: es dummy si y
  solo si `v_old = 0` y `v_new = 0`; no puede elegirse como etiqueta libre.
- El validador reconstruye las instancias públicas desde `TransferV2Effects` y
  el descriptor DKG activado: exige el `scheme_id`, `key_id` y epoch exactos y
  entrega al circuito las coordenadas canónicas de commitment, `C1`, `C2` y
  `PK_epoch`.
- El digest canónico completo de 256 bits de los efectos se conserva sin
  truncamiento como dos limbs públicos de 128 bits. De esta manera la prueba
  queda ligada también a chain ID, circuit ID, ciphertexts de nota y todos los
  bytes restantes.
- El paquete del prover conserva el `EncryptedNote` exacto que construyó y
  rechaza antes de probar cualquier divergencia byte a byte con los efectos.
- Paquete privado canónico `VAOP` v1 de 1.455 bytes para autorización de cada
  output. El signer compara un intent confiable y reconstruye por sí mismo la
  nota Ironwood V3, `cmx`, compromiso de valor, ephemeral key, ciphertext del
  receptor y ciphertext de recuperación; no acepta booleanos del coordinador.
- Clasificación fail-closed de payment, change y dummy: payment/change deben
  ser no cero; change/dummy deben pertenecer al scope interno del signer; dummy
  debe valer cero.
- Sesión opaca de firma transfer-v2 que fija red, circuito, esquema/key/epoch
  de burn, bucket de acciones, gas y techos de tarifa. Exige un token verificado
  para cada acción ordenada y liga cada firma a la clave de gasto y `rk`
  correctas.
- Pruebas adversariales rechazan paquetes truncados o mutados, tokens faltantes
  o reordenados, otra cuenta, otra autorización preparada y cualquier cambio
  de dominio, burn o gas antes de firmar.
- La ruta de sesión completa construye y verifica los cuatro buckets activados:
  2, 4, 8 y 16 acciones.
- Canal autenticado pre-emparejado
  `Noise_KK_25519_ChaChaPoly_BLAKE2s`, con identidades X25519 separadas de las
  claves VLT. El handshake hash liga challenge, contador durable, política,
  efectos y cada paquete privado a una sesión one-shot.
- Primer contacto con `Noise_XX_25519_ChaChaPoly_BLAKE2s`, fingerprint de
  transcript de 128 bits y confirmación fuera de banda. El tipo no confirmado
  no puede abrir KK; sólo la comparación correcta crea el registro canónico de
  peer confirmado.
- Registry de peers de tamaño exterior constante, cifrado y autenticado con
  XChaCha20-Poly1305. Conserva tombstones permanentes, rota una identidad nueva
  y confirmada en la misma transición que revoca la anterior, y es la única
  ruta pública que puede construir KK para un peer activo. Crear y abrir son
  operaciones separadas: el arranque normal falla si falta el registry y nunca
  lo reemplaza silenciosamente por uno vacío.
- Store Unix crash-consistent de 160 bytes que reserva la challenge exacta antes
  de exponerla y la consume antes de firmar. Usa lock exclusivo, archivos
  `0600`, rechazo de symlink/hardlink, checksum, reemplazo atómico y `fsync` del
  directorio; corrupción, replay o persistencia incierta fallan cerrados. El
  store faltante tampoco reinicia el contador: exige un flujo de recuperación
  explícito.
- Compact block canónico y acotado para wallet: transporta todos los outputs
  cifrados completos y nullifiers, se autentica contra un compromiso no circular
  del header finalizado, reproduce localmente la transición exacta del note tree
  y prueba cada output contra las viewing keys sin consultas específicas al
  servidor. El resultado para storage es atómico y los logs no revelan cuántas
  notas coincidieron.
- Cuentas de escaneo completas: cubren siempre recepción externa y cambio
  interno, asocian cada nota a un ID local cifrado y derivan su nullifier futuro
  para reconocer el gasto posterior sin preguntarle al nodo.
- Recuperación determinista de cuentas `0..N` desde seed sin guardar la seed ni
  spending keys: conserva sólo viewing keys, cubre hasta 64 cuentas mediante
  lotes criptográficos internos y vincula cada bloque al conjunto exacto de
  claves escaneado.
- Plan de recuperación ligado a birthday y target finalizados exactos, con
  progreso cifrado y durable `InProgress`/`Complete`/`RequiresLargerAccountRange`.
  Evalúa el gap sólo después de escanear todas las cuentas y alturas, bloquea
  witnesses mientras esté incompleto y exige reiniciar con un rango mayor si
  la actividad llega demasiado cerca del límite.
- Coordinador de recuperación acotado y reanudable: pide exactamente la altura
  siguiente al tip durable, exige un header que un adapter externo ya verificó
  por consenso/finality, limita y autentica bytes compactos hostiles, confirma
  cada commit antes de pedir el siguiente y reporta cuántos bloques anteriores
  quedaron durables si una fuente falla. No confunde quorum de RPC con finality.
- Primera base Unix transaccional SQLite/ShardTree: cifra y autentica cada
  payload privado con XChaCha20-Poly1305 y nonce fresco, indexa nullifiers con
  tags keyed, actualiza notas/spends/checkpoints/tip en una sola transacción,
  reconstruye root y posición al abrir, reconcilia notas no gastadas contra
  marks y entrega un witness Merkle actual verificado. Exige además un piso
  monotónico externo para rechazar snapshots demasiado antiguos.
- Codecs canónicos y acotados de request/response; el request máximo de 16
  acciones ocupa 37.352 bytes. Replay, reordenamiento, MITM, otra identidad,
  otra red, otro transcript o firma mutada envenenan/rechazan la sesión.
- La forma monolítica actual, con descriptor de época y digest completo, generó
  una prueba real de 9.600 bytes: 42,224 s de keygen provisional, 36,099 s de
  proving y 173 ms de verificación en una única medición local release.
- Benchmark RISC Zero: 256.266 bytes, 175,555 segundos de proving CPU, 262.144 ciclos
  totales y un segmento en Apple M1.

## Todavía no implementado

- Revisión independiente del pairing y ambos stores Unix ya implementados,
  adapters reales de keychain/secure element, perfiles no-Unix, UX confiable y
  dispositivos físicos. El cierre de sesiones, los contratos resistentes a
  rollback, el acuerdo multisig y la autorización/divulgación/revocación de
  proving delegado ya están congelados localmente, pero faltan sus adapters,
  corpora y evidencia externa. Un filesystem detecta corrupción, pero no puede
  detectar por sí solo la restauración maliciosa de un snapshot válido.
- Rotación y simulacros operativos del backup autenticado ya implementado;
  custodia/importación aprobada de seed y distribución confiable de birthday y
  target; adapter real de full node/light client, retrieval privado y política
  revisada para más de 64 cuentas; pruning/compactación y migraciones de la base
  ShardTree; keychain/secure element para su clave y piso anti-rollback;
  fault injection; y privacidad de retrieval/red contra IP, access patterns y
  correlación temporal.
- Consenso distribuido.
- Wallet segura.
- VaultVM, VaultSwap, atomic swaps o VaultStore.

Por eso el código todavía no debe manejar dinero real. La prueba monolítica ya
demuestra que los valores contables son los de las notas Action y que una salida
exenta vuelve al mismo receptor expandido privado. El compromiso y el
ciphertext de burn también usan la misma celda aritmética; la clave de época y
todos los efectos públicos ya son parte de la instancia reconstruida. La
validación independiente local de outputs definida en
[`NOTE_CIPHERTEXT_POLICY.md`](architecture/NOTE_CIPHERTEXT_POLICY.md) ya está
conectada a transfer-v2. El compact scanner finalizado también está conectado a
la transición exacta del árbol y su primera base transaccional cifrada mantiene
witnesses y estados de gasto reales. El backup V1 oculta identidad, tip y tamaño
exacto en un manifiesto cifrado, autentica chunks y padding, y restaura esa base
no vacía sin sobrescribir destinos. La recuperación birthday ahora exige una
frontera ligada a un header finalizado, conserva los ommers necesarios para
witnesses futuros y guarda el origen cifrado. La recuperación de cuentas ahora
es determinista, acotada y reanudable; vincula el conjunto exacto de viewing
keys y el target, y nunca libera witnesses ni afirma balance final mientras el
gap sea insuficiente. El coordinador ya autentica y confirma cada altura antes
de avanzar y reanuda desde el tip durable, pero aún falta el adapter que pruebe
finality con consenso real. El siguiente objetivo de wallet es cerrar
ese adapter, custodia/importación aprobada de seed, distribución confiable de checkpoints,
política para rangos mayores, operaciones y simulacros de backup, migraciones,
pruning/compactación, keychain/contador anti-rollback y pruebas de fallos; después cerrar
los corpora/harnesses finales de signer y proving delegado, y después ejecutar
en una sola campaña las pruebas externas de hardware, multisig, proving,
claves persistidas, memoria, todos los buckets y verificación por lotes.

## Decisión central

Vault utilizará un modelo append-only de notas y nullifiers inspirado en
protocolos desplegados como Orchard, y contratos privados basados en pruebas de
ejecución. Una zkVM general puede acelerar investigación y contratos; las
transferencias de dinero probablemente necesitarán circuitos especializados
para reducir coste. La decisión final se tomará con benchmarks reproducibles,
no por marketing.
