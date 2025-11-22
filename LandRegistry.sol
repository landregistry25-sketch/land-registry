// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract LandRegistry {
    struct Land {
        uint256 id;
        address owner;
        string location;
        string details;
        bool verified;
    }

    mapping(uint256 => Land) public lands;
    uint256 public landCount;

    event LandRegistered(uint256 landId, address owner);
    event LandVerified(uint256 landId);

    function registerLand(string memory location, string memory details) public {
        landCount++;
        lands[landCount] = Land(landCount, msg.sender, location, details, false);
        emit LandRegistered(landCount, msg.sender);
    }

    function verifyLand(uint256 landId) public {
        require(landId > 0 && landId <= landCount, "Invalid land ID");
        lands[landId].verified = true;
        emit LandVerified(landId);
    }

    function transferLand(uint256 landId, address newOwner) public {
        require(msg.sender == lands[landId].owner, "Not owner");
        require(lands[landId].verified, "Land not verified");
        lands[landId].owner = newOwner;
    }
}