(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_NOT_FOUND (err u101))
(define-constant ERR_ALREADY_EXISTS (err u102))
(define-constant ERR_INVALID_PERMISSION (err u103))
(define-constant ERR_EXPIRED (err u104))
(define-constant ERR_INVALID_LEVEL (err u105))
(define-constant ERR_INVALID_PARAMS (err u102))

(define-data-var audit-log-counter uint u0)

(define-data-var contract-active bool true)

(define-map kyc-records
  { user: principal }
  {
    verification-level: uint,
    verifier: principal,
    verified-at: uint,
    expires-at: uint,
    data-hash: (buff 32),
    is-active: bool
  }
)

(define-map app-permissions
  { user: principal, app: principal }
  {
    granted-at: uint,
    expires-at: uint,
    access-level: uint,
    is-active: bool
  }
)

(define-map authorized-verifiers
  { verifier: principal }
  {
    is-authorized: bool,
    authorized-at: uint,
    max-verification-level: uint
  }
)

(define-map app-registrations
  { app: principal }
  {
    name: (string-ascii 50),
    registered-at: uint,
    is-active: bool
  }
)

(define-read-only (get-contract-info)
  {
    owner: CONTRACT_OWNER,
    active: (var-get contract-active),
    stacks-block-height: stacks-block-height
  }
)

(define-read-only (is-contract-active)
  (var-get contract-active)
)

(define-public (toggle-contract-status)
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set contract-active (not (var-get contract-active)))
    (ok (var-get contract-active))
  )
)

(define-public (authorize-verifier (verifier principal) (max-level uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    (asserts! (<= max-level u5) ERR_INVALID_LEVEL)
    (map-set authorized-verifiers
      { verifier: verifier }
      {
        is-authorized: true,
        authorized-at: stacks-block-height,
        max-verification-level: max-level
      }
    )
    (ok true)
  )
)

(define-public (revoke-verifier (verifier principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    (match (map-get? authorized-verifiers { verifier: verifier })
      verifier-data (begin
        (map-set authorized-verifiers
          { verifier: verifier }
          (merge verifier-data { is-authorized: false })
        )
        (ok true)
      )
      ERR_NOT_FOUND
    )
  )
)

(define-read-only (is-authorized-verifier (verifier principal))
  (match (map-get? authorized-verifiers { verifier: verifier })
    verifier-data (get is-authorized verifier-data)
    false
  )
)

(define-public (register-app (name (string-ascii 50)))
  (begin
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    (asserts! (is-none (map-get? app-registrations { app: tx-sender })) ERR_ALREADY_EXISTS)
    (map-set app-registrations
      { app: tx-sender }
      {
        name: name,
        registered-at: stacks-block-height,
        is-active: true
      }
    )
    (ok true)
  )
)

(define-public (submit-kyc-verification 
  (user principal) 
  (verification-level uint) 
  (data-hash (buff 32)) 
  (validity-blocks uint))
  (begin
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    (asserts! (is-authorized-verifier tx-sender) ERR_UNAUTHORIZED)
    (asserts! (<= verification-level u5) ERR_INVALID_LEVEL)
    (asserts! (> validity-blocks u0) ERR_INVALID_PERMISSION)
    (match (map-get? authorized-verifiers { verifier: tx-sender })
      verifier-data (begin
        (asserts! (<= verification-level (get max-verification-level verifier-data)) ERR_INVALID_LEVEL)
        (map-set kyc-records
          { user: user }
          {
            verification-level: verification-level,
            verifier: tx-sender,
            verified-at: stacks-block-height,
            expires-at: (+ stacks-block-height validity-blocks),
            data-hash: data-hash,
            is-active: true
          }
        )
        (ok true)
      )
      ERR_UNAUTHORIZED
    )
  )
)

(define-public (revoke-kyc-verification (user principal))
  (begin
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    (match (map-get? kyc-records { user: user })
      record (begin
        (asserts! (or (is-eq tx-sender (get verifier record)) 
                     (is-eq tx-sender user) 
                     (is-eq tx-sender CONTRACT_OWNER)) ERR_UNAUTHORIZED)
        (map-set kyc-records
          { user: user }
          (merge record { is-active: false })
        )
        (ok true)
      )
      ERR_NOT_FOUND
    )
  )
)

(define-public (grant-app-permission 
  (app principal) 
  (access-level uint) 
  (validity-blocks uint))
  (begin
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    (asserts! (<= access-level u5) ERR_INVALID_LEVEL)
    (asserts! (> validity-blocks u0) ERR_INVALID_PERMISSION)
    (asserts! (is-some (map-get? app-registrations { app: app })) ERR_NOT_FOUND)
    (map-set app-permissions
      { user: tx-sender, app: app }
      {
        granted-at: stacks-block-height,
        expires-at: (+ stacks-block-height validity-blocks),
        access-level: access-level,
        is-active: true
      }
    )
    (ok true)
  )
)

(define-public (revoke-app-permission (app principal))
  (begin
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    (match (map-get? app-permissions { user: tx-sender, app: app })
      permission (begin
        (map-set app-permissions
          { user: tx-sender, app: app }
          (merge permission { is-active: false })
        )
        (ok true)
      )
      ERR_NOT_FOUND
    )
  )
)

(define-read-only (get-kyc-record (user principal))
  (map-get? kyc-records { user: user })
)

(define-read-only (check-kyc-status (user principal) (required-level uint))
  (match (map-get? kyc-records { user: user })
    record (and 
      (get is-active record)
      (>= (get verification-level record) required-level)
      (> (get expires-at record) stacks-block-height)
    )
    false
  )
)

(define-public (query-kyc-with-permission 
  (user principal) 
  (required-level uint))
  (begin
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    (match (map-get? app-permissions { user: user, app: tx-sender })
      permission (begin
        (asserts! (get is-active permission) ERR_INVALID_PERMISSION)
        (asserts! (> (get expires-at permission) stacks-block-height) ERR_EXPIRED)
        (asserts! (>= (get access-level permission) required-level) ERR_INVALID_LEVEL)
        (match (map-get? kyc-records { user: user })
          record (begin
            (asserts! (get is-active record) ERR_NOT_FOUND)
            (asserts! (> (get expires-at record) stacks-block-height) ERR_EXPIRED)
            (asserts! (>= (get verification-level record) required-level) ERR_INVALID_LEVEL)
            (ok {
              verification-level: (get verification-level record),
              verified-at: (get verified-at record),
              expires-at: (get expires-at record),
              verifier: (get verifier record)
            })
          )
          ERR_NOT_FOUND
        )
      )
      ERR_INVALID_PERMISSION
    )
  )
)

(define-read-only (get-app-permission (user principal) (app principal))
  (map-get? app-permissions { user: user, app: app })
)

(define-read-only (get-verifier-info (verifier principal))
  (map-get? authorized-verifiers { verifier: verifier })
)

(define-read-only (get-app-info (app principal))
  (map-get? app-registrations { app: app })
)

(define-read-only (is-kyc-valid (user principal) (min-level uint))
  (match (map-get? kyc-records { user: user })
    record (and
      (get is-active record)
      (>= (get verification-level record) min-level)
      (> (get expires-at record) stacks-block-height)
    )
    false
  )
)

(define-read-only (has-valid-permission (user principal) (app principal) (min-level uint))
  (match (map-get? app-permissions { user: user, app: app })
    permission (and
      (get is-active permission)
      (>= (get access-level permission) min-level)
      (> (get expires-at permission) stacks-block-height)
    )
    false
  )
)

(define-map audit-trail
  { log-id: uint }
  {
    event-type: (string-ascii 20),
    user: principal,
    verifier: principal,
    verification-level: uint,
    block-height: uint,
    timestamp: uint,
    data-hash: (buff 32),
    previous-level: uint
  }
)

(define-map user-audit-index
  { user: principal }
  { latest-log-id: uint, total-events: uint }
)

(define-private (log-verification-event
  (event-type (string-ascii 20))
  (user principal)
  (verifier principal)
  (verification-level uint)
  (data-hash (buff 32))
  (previous-level uint))
  (let ((current-counter (+ (var-get audit-log-counter) u1)))
    (var-set audit-log-counter current-counter)
    (map-set audit-trail
      { log-id: current-counter }
      {
        event-type: event-type,
        user: user,
        verifier: verifier,
        verification-level: verification-level,
        block-height: stacks-block-height,
        timestamp: stacks-block-height,
        data-hash: data-hash,
        previous-level: previous-level
      }
    )
    (match (map-get? user-audit-index { user: user })
      existing-index (map-set user-audit-index
        { user: user }
        { latest-log-id: current-counter, total-events: (+ (get total-events existing-index) u1) }
      )
      (map-set user-audit-index
        { user: user }
        { latest-log-id: current-counter, total-events: u1 }
      )
    )
    current-counter
  )
)

(define-public (log-kyc-verification
  (user principal)
  (verification-level uint)
  (data-hash (buff 32))
  (previous-level uint))
  (begin
    (asserts! (> verification-level u0) ERR_INVALID_PARAMS)
    (asserts! (<= verification-level u5) ERR_INVALID_PARAMS)
    (ok (log-verification-event "VERIFY" user tx-sender verification-level data-hash previous-level))
  )
)

(define-public (log-kyc-revocation (user principal) (previous-level uint))
  (begin
    (ok (log-verification-event "REVOKE" user tx-sender u0 0x00 previous-level))
  )
)

(define-read-only (get-audit-log (log-id uint))
  (map-get? audit-trail { log-id: log-id })
)

(define-read-only (get-user-audit-summary (user principal))
  (map-get? user-audit-index { user: user })
)

(define-read-only (get-verification-history (user principal) (count uint))
  (match (map-get? user-audit-index { user: user })
    index (let ((latest-id (get latest-log-id index)))
      (map get-audit-log (list (- latest-id u0) (- latest-id u1) (- latest-id u2) (- latest-id u3) (- latest-id u4)))
    )
    (list)
  )
)

(define-read-only (get-total-audit-events)
  (var-get audit-log-counter)
)

(define-read-only (get-recent-verifications (count uint))
  (if (and (<= count u10) (> count u0))
    (let ((current-counter (var-get audit-log-counter)))
      (if (> current-counter u0)
        (map get-audit-log
          (list
            (- current-counter u0) (- current-counter u1) (- current-counter u2)
            (- current-counter u3) (- current-counter u4) (- current-counter u5)
            (- current-counter u6) (- current-counter u7) (- current-counter u8)
            (- current-counter u9)
          )
        )
        (list)
      )
    )
    (list)
  )
)
