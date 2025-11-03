(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_NOT_FOUND (err u101))
(define-constant ERR_ALREADY_EXISTS (err u102))
(define-constant ERR_INVALID_PERMISSION (err u103))
(define-constant ERR_EXPIRED (err u104))
(define-constant ERR_INVALID_LEVEL (err u105))
(define-constant ERR_INVALID_PARAMS (err u102))

(define-constant MIN_REPUTATION u100)
(define-constant MAX_REPUTATION u1000)
(define-constant DEFAULT_REPUTATION u500)

(define-constant EXPIRY_WARNING_BLOCKS_30 u4320)
(define-constant EXPIRY_WARNING_BLOCKS_7 u1008) 
(define-constant EXPIRY_WARNING_BLOCKS_1 u144)

(define-constant MAX_BATCH_SIZE u10)
(define-constant MULTI_SIG_LEVEL_THRESHOLD u4)
(define-constant REQUIRED_APPROVALS u2)
(define-constant ERR_BATCH_TOO_LARGE (err u108))
(define-constant ERR_INSUFFICIENT_APPROVALS (err u109))

(define-data-var batch-counter uint u0)

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


(define-map expiry-notifications
  { notification-id: uint }
  {
    user: principal,
    expires-at: uint,
    warning-level: uint,
    notification-sent: bool,
    created-at: uint
  }
)

(define-map user-expiry-index
  { user: principal }
  { notification-id: uint, expires-at: uint }
)

(define-data-var notification-counter uint u0)

(define-private (register-expiry-notification (user principal) (expires-at uint))
  (let ((notification-id (+ (var-get notification-counter) u1)))
    (var-set notification-counter notification-id)
    (map-set expiry-notifications
      { notification-id: notification-id }
      {
        user: user,
        expires-at: expires-at,
        warning-level: u30,
        notification-sent: false,
        created-at: stacks-block-height
      }
    )
    (map-set user-expiry-index
      { user: user }
      { notification-id: notification-id, expires-at: expires-at }
    )
    notification-id
  )
)

(define-public (create-expiry-notification (user principal) (expires-at uint))
  (begin
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    (asserts! (is-authorized-verifier tx-sender) ERR_UNAUTHORIZED)
    (asserts! (> expires-at stacks-block-height) ERR_INVALID_PARAMS)
    (ok (register-expiry-notification user expires-at))
  )
)

(define-public (mark-notification-sent (notification-id uint))
  (begin
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    (match (map-get? expiry-notifications { notification-id: notification-id })
      notification (begin
        (map-set expiry-notifications
          { notification-id: notification-id }
          (merge notification { notification-sent: true })
        )
        (ok true)
      )
      ERR_NOT_FOUND
    )
  )
)

(define-read-only (get-expiry-notification (notification-id uint))
  (map-get? expiry-notifications { notification-id: notification-id })
)

(define-read-only (get-user-expiry-status (user principal))
  (map-get? user-expiry-index { user: user })
)

(define-read-only (check-expiry-warnings (warning-blocks uint))
  (let ((warning-threshold (+ stacks-block-height warning-blocks)))
    warning-threshold
  )
)

(define-read-only (is-expiring-soon (user principal) (warning-blocks uint))
  (match (map-get? user-expiry-index { user: user })
    expiry-info (< (get expires-at expiry-info) (+ stacks-block-height warning-blocks))
    false
  )
)


(define-map verifier-reputation
  { verifier: principal }
  {
    current-score: uint,
    total-verifications: uint,
    successful-verifications: uint,
    peer-reviews: uint,
    positive-reviews: uint,
    last-updated: uint
  }
)

(define-map reputation-reviews
  { reviewer: principal, verifier: principal }
  {
    score: uint,
    reviewed-at: uint,
    review-hash: (buff 32)
  }
)

(define-public (initialize-verifier-reputation (verifier principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (is-none (map-get? verifier-reputation { verifier: verifier })) ERR_ALREADY_EXISTS)
    (map-set verifier-reputation
      { verifier: verifier }
      {
        current-score: DEFAULT_REPUTATION,
        total-verifications: u0,
        successful-verifications: u0,
        peer-reviews: u0,
        positive-reviews: u0,
        last-updated: stacks-block-height
      }
    )
    (ok true)
  )
)

(define-public (update-verifier-reputation (verifier principal) (was-successful bool))
  (begin
    (asserts! (is-authorized-verifier tx-sender) ERR_UNAUTHORIZED)
    (match (map-get? verifier-reputation { verifier: verifier })
      rep-data (let
        (
          (new-total (+ (get total-verifications rep-data) u1))
          (new-successful (if was-successful (+ (get successful-verifications rep-data) u1) (get successful-verifications rep-data)))
          (success-rate (/ (* new-successful u100) new-total))
          (score-adjustment (if (> success-rate u80) u5 (if (< success-rate u60) (- u0 u10) u0)))
          (new-score (+ (get current-score rep-data) score-adjustment))
          (bounded-score (if (> new-score MAX_REPUTATION) MAX_REPUTATION (if (< new-score MIN_REPUTATION) MIN_REPUTATION new-score)))
        )
        (map-set verifier-reputation
          { verifier: verifier }
          (merge rep-data {
            current-score: bounded-score,
            total-verifications: new-total,
            successful-verifications: new-successful,
            last-updated: stacks-block-height
          })
        )
        (ok bounded-score)
      )
      ERR_NOT_FOUND
    )
  )
)

(define-public (submit-peer-review (verifier principal) (score uint) (review-hash (buff 32)))
  (begin
    (asserts! (is-authorized-verifier tx-sender) ERR_UNAUTHORIZED)
    (asserts! (not (is-eq tx-sender verifier)) ERR_INVALID_PARAMS)
    (asserts! (and (>= score u1) (<= score u10)) ERR_INVALID_PARAMS)
    (asserts! (is-none (map-get? reputation-reviews { reviewer: tx-sender, verifier: verifier })) ERR_ALREADY_EXISTS)
    (map-set reputation-reviews
      { reviewer: tx-sender, verifier: verifier }
      {
        score: score,
        reviewed-at: stacks-block-height,
        review-hash: review-hash
      }
    )
    (match (map-get? verifier-reputation { verifier: verifier })
      rep-data (begin
        (map-set verifier-reputation
          { verifier: verifier }
          (merge rep-data {
            peer-reviews: (+ (get peer-reviews rep-data) u1),
            positive-reviews: (if (>= score u7) (+ (get positive-reviews rep-data) u1) (get positive-reviews rep-data))
          })
        )
        (ok true)
      )
      ERR_NOT_FOUND
    )
  )
)

(define-read-only (get-verifier-reputation (verifier principal))
  (map-get? verifier-reputation { verifier: verifier })
)

(define-read-only (get-reputation-score (verifier principal))
  (match (map-get? verifier-reputation { verifier: verifier })
    rep-data (get current-score rep-data)
    DEFAULT_REPUTATION
  )
)


(define-map kyc-challenges
  { challenge-id: uint }
  {
    user: principal,
    challenged-verifier: principal,
    reason-hash: (buff 32),
    created-at: uint,
    status: (string-ascii 10),
    votes-for: uint,
    votes-against: uint,
    resolved-at: uint
  }
)

(define-map challenge-votes
  { challenge-id: uint, voter: principal }
  { vote: bool, voted-at: uint }
)

(define-data-var challenge-counter uint u0)

(define-constant CHALLENGE_VOTE_THRESHOLD u3)
(define-constant ERR_ALREADY_VOTED (err u106))
(define-constant ERR_CHALLENGE_RESOLVED (err u107))

(define-public (submit-kyc-challenge (reason-hash (buff 32)))
  (begin
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    (match (map-get? kyc-records { user: tx-sender })
      record (let ((new-id (+ (var-get challenge-counter) u1)))
        (var-set challenge-counter new-id)
        (map-set kyc-challenges
          { challenge-id: new-id }
          {
            user: tx-sender,
            challenged-verifier: (get verifier record),
            reason-hash: reason-hash,
            created-at: stacks-block-height,
            status: "PENDING",
            votes-for: u0,
            votes-against: u0,
            resolved-at: u0
          }
        )
        (ok new-id)
      )
      ERR_NOT_FOUND
    )
  )
)

(define-public (vote-on-challenge (challenge-id uint) (vote-for bool))
  (begin
    (asserts! (is-authorized-verifier tx-sender) ERR_UNAUTHORIZED)
    (asserts! (is-none (map-get? challenge-votes { challenge-id: challenge-id, voter: tx-sender })) ERR_ALREADY_VOTED)
    (match (map-get? kyc-challenges { challenge-id: challenge-id })
      challenge (begin
        (asserts! (is-eq (get status challenge) "PENDING") ERR_CHALLENGE_RESOLVED)
        (map-set challenge-votes
          { challenge-id: challenge-id, voter: tx-sender }
          { vote: vote-for, voted-at: stacks-block-height }
        )
        (map-set kyc-challenges
          { challenge-id: challenge-id }
          (merge challenge {
            votes-for: (if vote-for (+ (get votes-for challenge) u1) (get votes-for challenge)),
            votes-against: (if vote-for (get votes-against challenge) (+ (get votes-against challenge) u1))
          })
        )
        (ok true)
      )
      ERR_NOT_FOUND
    )
  )
)

(define-public (resolve-challenge (challenge-id uint))
  (begin
    (match (map-get? kyc-challenges { challenge-id: challenge-id })
      challenge (let ((total-votes (+ (get votes-for challenge) (get votes-against challenge))))
        (asserts! (>= total-votes CHALLENGE_VOTE_THRESHOLD) ERR_INVALID_PARAMS)
        (asserts! (is-eq (get status challenge) "PENDING") ERR_CHALLENGE_RESOLVED)
        (if (> (get votes-for challenge) (get votes-against challenge))
          (begin
            (map-set kyc-challenges { challenge-id: challenge-id }
              (merge challenge { status: "UPHELD", resolved-at: stacks-block-height }))
            (match (map-get? kyc-records { user: (get user challenge) })
              record (begin
                (map-set kyc-records { user: (get user challenge) }
                  (merge record { is-active: false }))
                (ok true)
              )
              (ok true)
            )
          )
          (begin
            (map-set kyc-challenges { challenge-id: challenge-id }
              (merge challenge { status: "REJECTED", resolved-at: stacks-block-height }))
            (ok false)
          )
        )
      )
      ERR_NOT_FOUND
    )
  )
)

(define-read-only (get-challenge (challenge-id uint))
  (map-get? kyc-challenges { challenge-id: challenge-id })
)

(define-read-only (get-challenge-vote (challenge-id uint) (voter principal))
  (map-get? challenge-votes { challenge-id: challenge-id, voter: voter })
)

(define-map batch-verifications
  { batch-id: uint }
  {
    verifier: principal,
    created-at: uint,
    total-users: uint,
    processed-count: uint,
    status: (string-ascii 10)
  }
)

(define-map batch-users
  { batch-id: uint, user-index: uint }
  {
    user: principal,
    verification-level: uint,
    data-hash: (buff 32),
    validity-blocks: uint
  }
)

(define-map multi-sig-approvals
  { batch-id: uint, approver: principal }
  { approved-at: uint }
)

(define-private (process-batch-user
  (user-data { user: principal, verification-level: uint, data-hash: (buff 32), validity-blocks: uint, verifier: principal })
  (acc (response uint uint)))
  (begin
    (map-set kyc-records
      { user: (get user user-data) }
      {
        verification-level: (get verification-level user-data),
        verifier: (get verifier user-data),
        verified-at: stacks-block-height,
        expires-at: (+ stacks-block-height (get validity-blocks user-data)),
        data-hash: (get data-hash user-data),
        is-active: true
      }
    )
    (ok (+ (unwrap-panic acc) u1))
  )
)

(define-public (submit-batch-verification
  (users (list 10 { user: principal, level: uint, hash: (buff 32), validity: uint })))
  (let ((batch-id (+ (var-get batch-counter) u1)) (batch-size (len users)))
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    (asserts! (is-authorized-verifier tx-sender) ERR_UNAUTHORIZED)
    (asserts! (<= batch-size MAX_BATCH_SIZE) ERR_BATCH_TOO_LARGE)
    (asserts! (> batch-size u0) ERR_INVALID_PARAMS)
    (var-set batch-counter batch-id)
    (map-set batch-verifications
      { batch-id: batch-id }
      { verifier: tx-sender, created-at: stacks-block-height, total-users: batch-size, processed-count: u0, status: "PENDING" }
    )
    (ok batch-id)
  )
)

(define-public (approve-multi-sig-batch (batch-id uint))
  (begin
    (asserts! (is-authorized-verifier tx-sender) ERR_UNAUTHORIZED)
    (asserts! (is-none (map-get? multi-sig-approvals { batch-id: batch-id, approver: tx-sender })) ERR_ALREADY_EXISTS)
    (map-set multi-sig-approvals { batch-id: batch-id, approver: tx-sender } { approved-at: stacks-block-height })
    (ok true)
  )
)

(define-read-only (get-batch-info (batch-id uint))
  (map-get? batch-verifications { batch-id: batch-id })
)

(define-read-only (get-batch-approval (batch-id uint) (approver principal))
  (map-get? multi-sig-approvals { batch-id: batch-id, approver: approver })
)