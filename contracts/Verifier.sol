// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier2 {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 19642524115522290447760970021746675789341356000653265441069630957431566301675;
    uint256 constant alphay  = 15809037446102219312954435152879098683824559980020626143453387822004586242317;
    uint256 constant betax1  = 6402738102853475583969787773506197858266321704623454181848954418090577674938;
    uint256 constant betax2  = 3306678135584565297353192801602995509515651571902196852074598261262327790404;
    uint256 constant betay1  = 15158588411628049902562758796812667714664232742372443470614751812018801551665;
    uint256 constant betay2  = 4983765881427969364617654516554524254158908221590807345159959200407712579883;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 16415145311680587598825815032384304996323630704403029084317821987338252286423;
    uint256 constant deltax2 = 18571905985302090282406751717216722237604528443752247105930319953320058816560;
    uint256 constant deltay1 = 12128516590032394631325470824776745227021388551885991234704945182271430879382;
    uint256 constant deltay2 = 20190901160757880971535137637716189030964075978951622224588367450745875399713;

    
    uint256 constant IC0x = 18381938601800858812660123489345396505196933814670367000146227282368288403354;
    uint256 constant IC0y = 4768500303070120005337836787633457377026324514151040497082231975418797989954;
    
    uint256 constant IC1x = 9221719907765719730007591572381011653733284045302496468947149159278949824433;
    uint256 constant IC1y = 13137173783984890241738433455531405924054873654201169380839988242488711742184;
    
    uint256 constant IC2x = 11598241131692653845304096110200300133278509964142508925715798068693312194026;
    uint256 constant IC2y = 17214283435764506873191765647453963014349672164918788939357083881228420235189;
    
    uint256 constant IC3x = 17726252300038241471095067881736925574477970532399067309538796910036648658003;
    uint256 constant IC3y = 9489728205308886827840989450845138907807748484999285335583151422087242146977;
    
    uint256 constant IC4x = 9229613589706002600581720674982008246191028003904858763116751109664480610026;
    uint256 constant IC4y = 11134860871956342120779029743081618229429433261082517728815249066185673917265;
    
    uint256 constant IC5x = 1901840278218640138732606096440119962537033408212344826225521120330097552655;
    uint256 constant IC5y = 10117264372644098396380125572547404179365338278078719501143243406898431558706;
    
    uint256 constant IC6x = 2839167319291499886707948487133803541533296535503111588625690918307361812493;
    uint256 constant IC6y = 17379561330065810659831823190775480282272393950022712790259648626596436138281;
    
    uint256 constant IC7x = 3003825476510850305023484803528315341909617023585939184191524058256140626831;
    uint256 constant IC7y = 13862649106288727920141243353114842856459820933813181240979612383265239864616;
    
    uint256 constant IC8x = 19524719108417854262210007287786572588916731106743108457390295841847167290578;
    uint256 constant IC8y = 947323625542621098813290590741515086014342936854961578265683423919226622614;
    
    uint256 constant IC9x = 1514605448711032725989313997245096346744878764673963423643337579802586778883;
    uint256 constant IC9y = 449307019776107104159145166149206138631722017541435648893239599687051825166;
    
    uint256 constant IC10x = 19216349589422184623060254658689783455717236023232405858181807308882865418306;
    uint256 constant IC10y = 17107697589471896892520694408280654866285696806396558562464246132817688459348;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[10] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
