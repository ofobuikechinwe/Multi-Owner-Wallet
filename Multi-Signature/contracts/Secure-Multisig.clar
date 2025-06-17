;; Multi-Signature Treasury Wallet Smart Contract
;; 
;; A secure multi-signature wallet implementation that requires multiple owner approvals 
;; for executing transactions, managing owners, and modifying wallet parameters.
;; Features include transaction proposal, confirmation tracking, expiration handling,
;; owner management, and configurable approval thresholds.

;; ERROR CONSTANTS

(define-constant ERR-UNAUTHORIZED-ACCESS (err u100))
(define-constant ERR-INVALID-PARAMETER-VALUE (err u101))
(define-constant ERR-TRANSACTION-NOT-FOUND (err u102))
(define-constant ERR-TRANSACTION-ALREADY-EXECUTED (err u103))
(define-constant ERR-TRANSACTION-ALREADY-REJECTED (err u104))
(define-constant ERR-TRANSACTION-EXPIRED (err u105))
(define-constant ERR-INSUFFICIENT-CONTRACT-BALANCE (err u106))
(define-constant ERR-APPROVAL-THRESHOLD-TOO-HIGH (err u107))
(define-constant ERR-OWNER-ALREADY-EXISTS (err u108))
(define-constant ERR-OWNER-NOT-FOUND (err u109))
(define-constant ERR-ALREADY-CONFIRMED-BY-OWNER (err u110))
(define-constant ERR-NOT-CONFIRMED-BY-OWNER (err u111))
(define-constant ERR-INVALID-DATA-BUFFER (err u112))

;; GLOBAL STATE VARIABLES

;; Counter for generating unique transaction IDs
(define-data-var next-transaction-id uint u0)

;; Number of active wallet owners
(define-data-var active-owner-count uint u0)

;; Required number of confirmations for transaction execution
(define-data-var required-approval-threshold uint u0)

;; DATA STRUCTURES

;; Comprehensive transaction record structure
(define-map pending-transactions
  { transaction-id: uint }
  {
    proposal-creator: principal,
    destination-address: principal,
    transfer-amount: uint,
    attached-data: (optional (buff 256)),
    is-executed: bool,
    is-rejected: bool,
    current-confirmations: uint,
    expiration-block: uint
  }
)

;; Owner confirmation tracking for each transaction
(define-map owner-confirmations
  { transaction-id: uint, confirming-owner: principal }
  { has-confirmed: bool }
)

;; Active wallet owners registry
(define-map wallet-owners
  { owner-address: principal }
  { is-active-owner: bool }
)

;; VALIDATION HELPER FUNCTIONS

;; Validates data buffer size constraints
(define-private (validate-data-buffer (data-buffer (optional (buff 256))))
  (match data-buffer
    buffer-content (if (< (len buffer-content) u256) 
                      (some buffer-content)
                      none)
    none))

;; Checks if the calling principal is an authorized owner
(define-private (validate-sender-is-owner)
  (is-wallet-owner tx-sender))

;; Adds an owner during contract initialization
(define-private (register-initial-owner (owner-address principal))
  (begin
    (map-set wallet-owners { owner-address: owner-address } { is-active-owner: true })
    (var-set active-owner-count (+ (var-get active-owner-count) u1))
    true
  )
)

;; CONTRACT INITIALIZATION

;; Initialize the multi-signature wallet with owners and approval threshold
(define-public (initialize-wallet (initial-owner-list (list 20 principal)) (approval-threshold uint))
  (begin
    ;; Ensure contract hasn't been initialized yet
    (asserts! (is-eq (var-get active-owner-count) u0) ERR-UNAUTHORIZED-ACCESS)
    ;; Validate threshold doesn't exceed owner count
    (asserts! (<= approval-threshold (len initial-owner-list)) ERR-APPROVAL-THRESHOLD-TOO-HIGH)
    ;; Ensure threshold is at least 1
    (asserts! (> approval-threshold u0) ERR-INVALID-PARAMETER-VALUE)
    
    ;; Set the required approval threshold
    (var-set required-approval-threshold approval-threshold)
    
    ;; Register all initial owners
    (map register-initial-owner initial-owner-list)
    
    ;; Return successful initialization
    (ok true)
  )
)

;; READ-ONLY QUERY FUNCTIONS

;; Get current approval threshold setting
(define-read-only (get-approval-threshold)
  (var-get required-approval-threshold)
)

;; Check if an address is an authorized wallet owner
(define-read-only (is-wallet-owner (address principal))
  (default-to false (get is-active-owner (map-get? wallet-owners { owner-address: address })))
)

;; Get total number of active owners
(define-read-only (get-active-owner-count)
  (var-get active-owner-count)
)

;; Retrieve complete transaction details
(define-read-only (get-transaction-details (transaction-id uint))
  (map-get? pending-transactions { transaction-id: transaction-id })
)

;; Check if a transaction exists in the system
(define-read-only (does-transaction-exist (transaction-id uint))
  (is-some (map-get? pending-transactions { transaction-id: transaction-id }))
)

;; Check if an owner has confirmed a specific transaction
(define-read-only (has-owner-confirmed (transaction-id uint) (owner-address principal))
  (default-to false 
    (get has-confirmed 
      (map-get? owner-confirmations { transaction-id: transaction-id, confirming-owner: owner-address })))
)

;; Get current confirmation count for a transaction
(define-read-only (get-transaction-confirmation-count (transaction-id uint))
  (match (map-get? pending-transactions { transaction-id: transaction-id })
    transaction-record (get current-confirmations transaction-record)
    u0
  )
)

;; Get contract's current STX balance
(define-read-only (get-contract-balance)
  (stx-get-balance (as-contract tx-sender))
)

;; TRANSACTION MANAGEMENT FUNCTIONS

;; Submit a new transaction proposal for owner approval
(define-public (propose-transaction (destination-address principal) (transfer-amount uint) 
                                   (attached-data (optional (buff 256))) (expiration-block uint))
  (let
    (
      (current-transaction-id (var-get next-transaction-id))
      (contract-address (as-contract tx-sender))
      (validated-data-buffer (validate-data-buffer attached-data))
    )
    ;; Verify sender is authorized owner
    (asserts! (validate-sender-is-owner) ERR-UNAUTHORIZED-ACCESS)
    ;; Ensure expiration is in the future
    (asserts! (> expiration-block block-height) ERR-INVALID-PARAMETER-VALUE)
    ;; Prevent self-transfers to contract
    (asserts! (not (is-eq destination-address contract-address)) ERR-INVALID-PARAMETER-VALUE)
    ;; Ensure transfer amount is positive
    (asserts! (> transfer-amount u0) ERR-INVALID-PARAMETER-VALUE)
    ;; Verify contract has sufficient funds
    (asserts! (<= transfer-amount (stx-get-balance contract-address)) ERR-INSUFFICIENT-CONTRACT-BALANCE)
    ;; Validate data buffer format
    (asserts! (is-some validated-data-buffer) ERR-INVALID-DATA-BUFFER)
    
    ;; Create new transaction record
    (map-set pending-transactions
      { transaction-id: current-transaction-id }
      {
        proposal-creator: tx-sender,
        destination-address: destination-address,
        transfer-amount: transfer-amount,
        attached-data: validated-data-buffer,
        is-executed: false,
        is-rejected: false,
        current-confirmations: u1, ;; Creator automatically confirms
        expiration-block: expiration-block
      }
    )
    
    ;; Record creator's automatic confirmation
    (map-set owner-confirmations
      { transaction-id: current-transaction-id, confirming-owner: tx-sender }
      { has-confirmed: true }
    )
    
    ;; Increment transaction ID counter
    (var-set next-transaction-id (+ current-transaction-id u1))
    
    ;; Auto-execute if threshold is 1, otherwise return transaction ID
    (if (is-eq (var-get required-approval-threshold) u1)
      (let ((execution-result (execute-pending-transaction current-transaction-id)))
        (ok current-transaction-id))
      (ok current-transaction-id)
    )
  )
)

;; Confirm approval for a pending transaction
(define-public (confirm-transaction-approval (transaction-id uint))
  (begin
    ;; Verify sender is authorized owner
    (asserts! (validate-sender-is-owner) ERR-UNAUTHORIZED-ACCESS)
    ;; Ensure transaction exists
    (asserts! (does-transaction-exist transaction-id) ERR-TRANSACTION-NOT-FOUND)
    
    ;; Process confirmation with transaction data
    (match (map-get? pending-transactions { transaction-id: transaction-id })
      transaction-record
        (begin
          ;; Verify transaction is still pending
          (asserts! (not (get is-executed transaction-record)) ERR-TRANSACTION-ALREADY-EXECUTED)
          (asserts! (not (get is-rejected transaction-record)) ERR-TRANSACTION-ALREADY-REJECTED)
          ;; Check transaction hasn't expired
          (asserts! (<= block-height (get expiration-block transaction-record)) ERR-TRANSACTION-EXPIRED)
          ;; Ensure owner hasn't already confirmed
          (asserts! (not (has-owner-confirmed transaction-id tx-sender)) ERR-ALREADY-CONFIRMED-BY-OWNER)
          
          ;; Record owner's confirmation
          (map-set owner-confirmations
            { transaction-id: transaction-id, confirming-owner: tx-sender }
            { has-confirmed: true }
          )
          
          ;; Update transaction confirmation count
          (map-set pending-transactions
            { transaction-id: transaction-id }
            (merge transaction-record { current-confirmations: (+ (get current-confirmations transaction-record) u1) })
          )
          
          ;; Execute transaction if threshold reached
          (if (>= (+ (get current-confirmations transaction-record) u1) (var-get required-approval-threshold))
            (let ((execution-result (execute-pending-transaction transaction-id)))
              (ok transaction-id))
            (ok transaction-id)
          )
        )
      ERR-TRANSACTION-NOT-FOUND
    )
  )
)

;; Revoke a previously given confirmation
(define-public (revoke-transaction-confirmation (transaction-id uint))
  (begin
    ;; Verify sender is authorized owner
    (asserts! (validate-sender-is-owner) ERR-UNAUTHORIZED-ACCESS)
    ;; Ensure transaction exists
    (asserts! (does-transaction-exist transaction-id) ERR-TRANSACTION-NOT-FOUND)
    
    ;; Process revocation with transaction data
    (match (map-get? pending-transactions { transaction-id: transaction-id })
      transaction-record
        (begin
          ;; Verify transaction is still pending
          (asserts! (not (get is-executed transaction-record)) ERR-TRANSACTION-ALREADY-EXECUTED)
          (asserts! (not (get is-rejected transaction-record)) ERR-TRANSACTION-ALREADY-REJECTED)
          ;; Ensure owner has previously confirmed
          (asserts! (has-owner-confirmed transaction-id tx-sender) ERR-NOT-CONFIRMED-BY-OWNER)
          
          ;; Remove owner's confirmation
          (map-set owner-confirmations
            { transaction-id: transaction-id, confirming-owner: tx-sender }
            { has-confirmed: false }
          )
          
          ;; Update transaction confirmation count
          (map-set pending-transactions
            { transaction-id: transaction-id }
            (merge transaction-record { current-confirmations: (- (get current-confirmations transaction-record) u1) })
          )
          
          (ok transaction-id)
        )
      ERR-TRANSACTION-NOT-FOUND
    )
  )
)

;; Execute a transaction that has met the approval threshold
(define-public (execute-pending-transaction (transaction-id uint))
  (begin
    ;; Ensure transaction exists
    (asserts! (does-transaction-exist transaction-id) ERR-TRANSACTION-NOT-FOUND)
    
    ;; Process execution with transaction data
    (match (map-get? pending-transactions { transaction-id: transaction-id })
      transaction-record
        (begin
          ;; Verify transaction is still pending
          (asserts! (not (get is-executed transaction-record)) ERR-TRANSACTION-ALREADY-EXECUTED)
          (asserts! (not (get is-rejected transaction-record)) ERR-TRANSACTION-ALREADY-REJECTED)
          ;; Check transaction hasn't expired
          (asserts! (<= block-height (get expiration-block transaction-record)) ERR-TRANSACTION-EXPIRED)
          ;; Verify approval threshold is met
          (asserts! (>= (get current-confirmations transaction-record) (var-get required-approval-threshold)) ERR-UNAUTHORIZED-ACCESS)
          
          ;; Mark transaction as executed
          (map-set pending-transactions
            { transaction-id: transaction-id }
            (merge transaction-record { is-executed: true })
          )
          
          ;; Execute the STX transfer
          (as-contract 
            (stx-transfer? (get transfer-amount transaction-record) tx-sender (get destination-address transaction-record))
          )
        )
      ERR-TRANSACTION-NOT-FOUND
    )
  )
)

;; Reject a pending transaction
(define-public (reject-pending-transaction (transaction-id uint))
  (begin
    ;; Verify sender is authorized owner
    (asserts! (validate-sender-is-owner) ERR-UNAUTHORIZED-ACCESS)
    ;; Ensure transaction exists
    (asserts! (does-transaction-exist transaction-id) ERR-TRANSACTION-NOT-FOUND)
    
    ;; Process rejection with transaction data
    (match (map-get? pending-transactions { transaction-id: transaction-id })
      transaction-record
        (begin
          ;; Verify transaction is still pending
          (asserts! (not (get is-executed transaction-record)) ERR-TRANSACTION-ALREADY-EXECUTED)
          (asserts! (not (get is-rejected transaction-record)) ERR-TRANSACTION-ALREADY-REJECTED)
          ;; Check transaction hasn't expired
          (asserts! (<= block-height (get expiration-block transaction-record)) ERR-TRANSACTION-EXPIRED)
          
          ;; Allow creator to reject their own transaction, otherwise require threshold
          (if (is-eq (get proposal-creator transaction-record) tx-sender)
            (begin
              (map-set pending-transactions
                { transaction-id: transaction-id }
                (merge transaction-record { is-rejected: true })
              )
              (ok transaction-id)
            )
            ;; Require threshold confirmations for rejection by others
            (if (>= (get current-confirmations transaction-record) (var-get required-approval-threshold))
              (begin
                (map-set pending-transactions
                  { transaction-id: transaction-id }
                  (merge transaction-record { is-rejected: true })
                )
                (ok transaction-id)
              )
              ERR-UNAUTHORIZED-ACCESS
            )
          )
        )
      ERR-TRANSACTION-NOT-FOUND
    )
  )
)

;; OWNER MANAGEMENT FUNCTIONS

;; Propose adding a new wallet owner
(define-public (propose-add-owner (new-owner-address principal))
  (let
    (
      (current-transaction-id (var-get next-transaction-id))
    )
    ;; Verify sender is authorized owner
    (asserts! (validate-sender-is-owner) ERR-UNAUTHORIZED-ACCESS)
    ;; Ensure new owner doesn't already exist
    (asserts! (not (is-wallet-owner new-owner-address)) ERR-OWNER-ALREADY-EXISTS)
    
    ;; Create governance transaction for adding owner
    (map-set pending-transactions
      { transaction-id: current-transaction-id }
      {
        proposal-creator: tx-sender,
        destination-address: new-owner-address, ;; Store new owner address
        transfer-amount: u0,
        attached-data: none,
        is-executed: false,
        is-rejected: false,
        current-confirmations: u1, ;; Creator automatically confirms
        expiration-block: (+ block-height u144) ;; Approximately 1 day expiration
      }
    )
    
    ;; Record creator's automatic confirmation
    (map-set owner-confirmations
      { transaction-id: current-transaction-id, confirming-owner: tx-sender }
      { has-confirmed: true }
    )
    
    ;; Increment transaction ID counter
    (var-set next-transaction-id (+ current-transaction-id u1))
    
    (ok current-transaction-id)
  )
)

;; Execute the addition of a new owner (internal governance function)
(define-public (execute-add-owner-proposal (transaction-id uint))
  (begin
    ;; Ensure transaction exists
    (asserts! (does-transaction-exist transaction-id) ERR-TRANSACTION-NOT-FOUND)
    
    ;; Process owner addition with transaction data
    (match (map-get? pending-transactions { transaction-id: transaction-id })
      transaction-record
        (begin
          ;; Verify transaction is still pending
          (asserts! (not (get is-executed transaction-record)) ERR-TRANSACTION-ALREADY-EXECUTED)
          (asserts! (not (get is-rejected transaction-record)) ERR-TRANSACTION-ALREADY-REJECTED)
          ;; Check transaction hasn't expired
          (asserts! (<= block-height (get expiration-block transaction-record)) ERR-TRANSACTION-EXPIRED)
          ;; Verify approval threshold is met
          (asserts! (>= (get current-confirmations transaction-record) (var-get required-approval-threshold)) ERR-UNAUTHORIZED-ACCESS)
          
          ;; Mark transaction as executed
          (map-set pending-transactions
            { transaction-id: transaction-id }
            (merge transaction-record { is-executed: true })
          )
          
          ;; Add new owner to registry
          (map-set wallet-owners 
            { owner-address: (get destination-address transaction-record) } 
            { is-active-owner: true }
          )
          
          ;; Increment active owner count
          (var-set active-owner-count (+ (var-get active-owner-count) u1))
          
          (ok transaction-id)
        )
      ERR-TRANSACTION-NOT-FOUND
    )
  )
)

;; Propose removing an existing wallet owner
(define-public (propose-remove-owner (owner-to-remove principal))
  (let
    (
      (current-transaction-id (var-get next-transaction-id))
    )
    ;; Verify sender is authorized owner
    (asserts! (validate-sender-is-owner) ERR-UNAUTHORIZED-ACCESS)
    ;; Ensure target owner exists
    (asserts! (is-wallet-owner owner-to-remove) ERR-OWNER-NOT-FOUND)
    ;; Prevent removing the last owner
    (asserts! (> (var-get active-owner-count) u1) ERR-INVALID-PARAMETER-VALUE)
    ;; Ensure threshold remains valid after removal
    (asserts! (<= (var-get required-approval-threshold) (- (var-get active-owner-count) u1)) ERR-APPROVAL-THRESHOLD-TOO-HIGH)
    
    ;; Create governance transaction for removing owner
    (map-set pending-transactions
      { transaction-id: current-transaction-id }
      {
        proposal-creator: tx-sender,
        destination-address: owner-to-remove, ;; Store owner to remove
        transfer-amount: u0,
        attached-data: none,
        is-executed: false,
        is-rejected: false,
        current-confirmations: u1, ;; Creator automatically confirms
        expiration-block: (+ block-height u144) ;; Approximately 1 day expiration
      }
    )
    
    ;; Record creator's automatic confirmation
    (map-set owner-confirmations
      { transaction-id: current-transaction-id, confirming-owner: tx-sender }
      { has-confirmed: true }
    )
    
    ;; Increment transaction ID counter
    (var-set next-transaction-id (+ current-transaction-id u1))
    
    (ok current-transaction-id)
  )
)

;; Execute the removal of an owner (internal governance function)
(define-public (execute-remove-owner-proposal (transaction-id uint))
  (begin
    ;; Ensure transaction exists
    (asserts! (does-transaction-exist transaction-id) ERR-TRANSACTION-NOT-FOUND)
    
    ;; Process owner removal with transaction data
    (match (map-get? pending-transactions { transaction-id: transaction-id })
      transaction-record
        (begin
          ;; Verify transaction is still pending
          (asserts! (not (get is-executed transaction-record)) ERR-TRANSACTION-ALREADY-EXECUTED)
          (asserts! (not (get is-rejected transaction-record)) ERR-TRANSACTION-ALREADY-REJECTED)
          ;; Check transaction hasn't expired
          (asserts! (<= block-height (get expiration-block transaction-record)) ERR-TRANSACTION-EXPIRED)
          ;; Verify approval threshold is met
          (asserts! (>= (get current-confirmations transaction-record) (var-get required-approval-threshold)) ERR-UNAUTHORIZED-ACCESS)
          
          ;; Mark transaction as executed
          (map-set pending-transactions
            { transaction-id: transaction-id }
            (merge transaction-record { is-executed: true })
          )
          
          ;; Remove owner from registry
          (map-set wallet-owners 
            { owner-address: (get destination-address transaction-record) } 
            { is-active-owner: false }
          )
          
          ;; Decrement active owner count
          (var-set active-owner-count (- (var-get active-owner-count) u1))
          
          (ok transaction-id)
        )
      ERR-TRANSACTION-NOT-FOUND
    )
  )
)

;; GOVERNANCE FUNCTIONS

;; Propose changing the approval threshold
(define-public (propose-threshold-change (new-threshold uint))
  (let
    (
      (current-transaction-id (var-get next-transaction-id))
    )
    ;; Verify sender is authorized owner
    (asserts! (validate-sender-is-owner) ERR-UNAUTHORIZED-ACCESS)
    ;; Validate new threshold parameters
    (asserts! (> new-threshold u0) ERR-INVALID-PARAMETER-VALUE)
    (asserts! (<= new-threshold (var-get active-owner-count)) ERR-APPROVAL-THRESHOLD-TOO-HIGH)
    
    ;; Create governance transaction for threshold change
    (map-set pending-transactions
      { transaction-id: current-transaction-id }
      {
        proposal-creator: tx-sender,
        destination-address: tx-sender, ;; Not relevant for this operation
        transfer-amount: new-threshold, ;; Store new threshold value
        attached-data: none,
        is-executed: false,
        is-rejected: false,
        current-confirmations: u1, ;; Creator automatically confirms
        expiration-block: (+ block-height u144) ;; Approximately 1 day expiration
      }
    )
    
    ;; Record creator's automatic confirmation
    (map-set owner-confirmations
      { transaction-id: current-transaction-id, confirming-owner: tx-sender }
      { has-confirmed: true }
    )
    
    ;; Increment transaction ID counter
    (var-set next-transaction-id (+ current-transaction-id u1))
    
    (ok current-transaction-id)
  )
)

;; Execute the threshold change (internal governance function)
(define-public (execute-threshold-change-proposal (transaction-id uint))
  (begin
    ;; Ensure transaction exists
    (asserts! (does-transaction-exist transaction-id) ERR-TRANSACTION-NOT-FOUND)
    
    ;; Process threshold change with transaction data
    (match (map-get? pending-transactions { transaction-id: transaction-id })
      transaction-record
        (begin
          ;; Verify transaction is still pending
          (asserts! (not (get is-executed transaction-record)) ERR-TRANSACTION-ALREADY-EXECUTED)
          (asserts! (not (get is-rejected transaction-record)) ERR-TRANSACTION-ALREADY-REJECTED)
          ;; Check transaction hasn't expired
          (asserts! (<= block-height (get expiration-block transaction-record)) ERR-TRANSACTION-EXPIRED)
          ;; Verify approval threshold is met
          (asserts! (>= (get current-confirmations transaction-record) (var-get required-approval-threshold)) ERR-UNAUTHORIZED-ACCESS)
          
          ;; Mark transaction as executed
          (map-set pending-transactions
            { transaction-id: transaction-id }
            (merge transaction-record { is-executed: true })
          )
          
          ;; Update approval threshold
          (var-set required-approval-threshold (get transfer-amount transaction-record))
          
          (ok transaction-id)
        )
      ERR-TRANSACTION-NOT-FOUND
    )
  )
)


;; TREASURY MANAGEMENT FUNCTIONS


;; Deposit STX tokens into the wallet contract
(define-public (deposit-funds (deposit-amount uint))
  (begin
    (stx-transfer? deposit-amount tx-sender (as-contract tx-sender))
  )
)

;; Remove expired transactions to maintain contract cleanliness
(define-public (cleanup-expired-transaction (transaction-id uint))
  (begin
    ;; Verify sender is authorized owner
    (asserts! (validate-sender-is-owner) ERR-UNAUTHORIZED-ACCESS)
    ;; Ensure transaction exists
    (asserts! (does-transaction-exist transaction-id) ERR-TRANSACTION-NOT-FOUND)
    
    ;; Process cleanup with transaction data
    (match (map-get? pending-transactions { transaction-id: transaction-id })
      transaction-record
        (begin
          ;; Verify transaction is still pending
          (asserts! (not (get is-executed transaction-record)) ERR-TRANSACTION-ALREADY-EXECUTED)
          (asserts! (not (get is-rejected transaction-record)) ERR-TRANSACTION-ALREADY-REJECTED)
          ;; Verify transaction has actually expired
          (asserts! (> block-height (get expiration-block transaction-record)) ERR-INVALID-PARAMETER-VALUE)
          
          ;; Mark expired transaction as rejected
          (map-set pending-transactions
            { transaction-id: transaction-id }
            (merge transaction-record { is-rejected: true })
          )
          
          (ok transaction-id)
        )
      ERR-TRANSACTION-NOT-FOUND
    )
  )
)