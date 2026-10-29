// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Authentication {
    address public trustedAuthority;

    struct Vehicle {
        bytes32 RID;
        bytes32 PID;
        address ppk;
        bool isRegistered;
    }

    struct CMTNode {
        bytes32 hash;
        uint256 timestamp;
    }

    struct Message {
        bytes32 PID;
        string content;
        uint256 timestamp;
    }

    mapping(bytes32 => Vehicle) private vehicleRegistry;
    mapping(bytes32 => Message) public authenticatedMessages;
    CMTNode[] public cmt;
    bytes32 public currentRoot;

    event VehicleRegistered(bytes32 RID, bytes32 PID);
    event VehicleAuthenticated(bytes32 RID, bytes32 PID);
    event CMTUpdated(bytes32 rootHash);
    event MessageAuthenticated(bytes32 RID, bytes32 PID, string content, uint256 timestamp);
    event Debug(bytes32 messageHash, address recoveredSigner);

    modifier onlyTrustedAuthority() {
        require(msg.sender == trustedAuthority, "Caller is not the Trusted Authority");
        _; }

    modifier onlyRegistered(bytes32 _RID) {
        require(vehicleRegistry[_RID].isRegistered, "Vehicle is not registered");
        _;  }

    constructor(address _trustedAuthority) {
        require(_trustedAuthority != address(0), "Invalid Trusted Authority address");
        trustedAuthority = _trustedAuthority;
        currentRoot = bytes32(0);
    }

    function registerVehicle(bytes32 _RID, address _ppk) public onlyTrustedAuthority {
        require(!vehicleRegistry[_RID].isRegistered, "Vehicle is already registered");
        require(_RID != bytes32(0), "Invalid RID");

        bytes32 _PID = keccak256(abi.encodePacked(_RID, block.timestamp));
        vehicleRegistry[_RID] = Vehicle({
            RID: _RID,
            PID: _PID,
            ppk: _ppk,
            isRegistered: true
        });
        emit VehicleRegistered(_RID, _PID);
    }

    function authenticateVehicle(bytes32 _RID, bytes32 _PID) public onlyRegistered(_RID) {
        require(vehicleRegistry[_RID].PID == _PID, "Invalid PID for the vehicle");

        bytes32 nodeHash = keccak256(abi.encodePacked(_RID, _PID, block.timestamp));
        cmt.push(CMTNode({hash: nodeHash, timestamp: block.timestamp}));
        currentRoot = keccak256(abi.encodePacked(currentRoot, nodeHash));

        emit VehicleAuthenticated(_RID, _PID);
        emit CMTUpdated(currentRoot);
    }

    function authenticateMessage(
        bytes32 _RID,
        bytes32 _PID,
        string memory _content,
        uint256 _timestamp,
        bytes memory _signature
    ) public onlyRegistered(_RID) returns (bool) {
        Vehicle storage vehicle = vehicleRegistry[_RID];
        require(block.timestamp - _timestamp < 300, "Message is too old");

        bytes32 messageHash = keccak256(abi.encodePacked(_content, _timestamp, vehicle.PID));
        address recoveredSigner = recoverSigner(messageHash, _signature);

        emit Debug(messageHash, recoveredSigner);
        require(recoveredSigner == vehicle.ppk, "Invalid signature");
        authenticatedMessages[messageHash] = Message({
            PID: _PID,
            content: _content,
            timestamp: _timestamp
        });
        emit MessageAuthenticated(_RID, _PID, _content, _timestamp);
        return true;
    }

    function recoverSigner(bytes32 _messageHash, bytes memory _signature) internal pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_messageHash, v, r, s);
    }

    function splitSignature(bytes memory _signature) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(_signature.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
            v := byte(0, mload(add(_signature, 96)))
        }
    }

    function getPseudonym(bytes32 _RID) public view onlyRegistered(_RID) returns (bytes32) {
        return vehicleRegistry[_RID].PID;
    }

    function isVehicleRegistered(bytes32 _RID) public view returns (bool) {
        return vehicleRegistry[_RID].isRegistered;
    }
}
