// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title BallotRegistry
/// @notice Operator-written round metadata for CRISP FHE multi-option voting.
///         Lives on the operator-controlled chain alongside CRISPQESProgram.
///         Holds the question + option labels + the Base Sepolia enrollment-root
///         snapshot the round is bound to, so the web can render ballots and
///         third parties can audit what was voted on.
contract BallotRegistry {
    struct Round {
        string question;
        string[] optionLabels;
        bytes32 enrollmentRoot; // snapshot of Base Sepolia EnrollmentRegistry.enrollmentRoot()
        uint64 deadline;        // unix seconds
        uint32 numOptions;
        bool exists;
    }

    address public immutable operator;
    mapping(uint256 => Round) private rounds; // e3Id => Round
    uint256[] public roundIds;

    error NotOperator();
    error RoundExists();
    error TooFewOptions();

    event RoundCreated(uint256 indexed e3Id, uint32 numOptions, bytes32 enrollmentRoot, uint64 deadline);

    constructor(address operator_) {
        operator = operator_;
    }

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    function createRound(
        uint256 e3Id,
        string calldata question,
        string[] calldata optionLabels,
        bytes32 enrollmentRoot,
        uint64 deadline
    ) external onlyOperator {
        if (rounds[e3Id].exists) revert RoundExists();
        if (optionLabels.length < 2) revert TooFewOptions();
        Round storage r = rounds[e3Id];
        r.question = question;
        for (uint256 i = 0; i < optionLabels.length; i++) r.optionLabels.push(optionLabels[i]);
        r.enrollmentRoot = enrollmentRoot;
        r.deadline = deadline;
        r.numOptions = uint32(optionLabels.length);
        r.exists = true;
        roundIds.push(e3Id);
        emit RoundCreated(e3Id, r.numOptions, enrollmentRoot, deadline);
    }

    function getRound(uint256 e3Id) external view returns (Round memory) {
        return rounds[e3Id];
    }

    function roundCount() external view returns (uint256) {
        return roundIds.length;
    }
}
