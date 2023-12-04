// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.13;

library AggregatorLib {
    uint256 constant q_mod = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant p_mod = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function check_on_curve(uint256 x, uint256 y) internal pure {
        if (x != 0 && y != 0) {
            uint256 l = mulmod(y, y, q_mod);
            uint256 r = mulmod(x, x, q_mod);
            r = mulmod(r, x, q_mod);
            r = addmod(r, 3, q_mod);

            assert(l == r);
        }
    }

    function pairing(uint256[] memory input) internal view returns (bool) {
        uint256[1] memory result;
        bool ret;

        uint256 length = input.length * 0x20;
        assembly {
            ret := staticcall(gas(), 8, add(input, 0x20), length, result, 0x20)
        }
        require(ret);
        return result[0] != 0;
    }

    // The result will replaced at input[offset]
    // memory will be modified.
    function msm(
        uint256[] memory input,
        uint256 offset,
        uint256 count
    ) internal view {
        if (count == 0) {
            input[offset] = 0;
            input[offset + 1] = 0;
            return;
        }

        bool ret = false;
        offset = offset * 0x20 + 0x20;
        uint256 start = offset + count * 0x60 - 0x60;

        assembly {
            ret := staticcall(
                gas(),
                7,
                add(input, start),
                0x60,
                add(input, start),
                0x40
            )
        }
        require(ret);

        while (start != offset) {
            start -= 0x60;
            assembly {
                ret := staticcall(
                    gas(),
                    7,
                    add(input, start),
                    0x60,
                    add(input, add(start, 0x20)),
                    0x40
                )
            }
            require(ret);

            assembly {
                ret := staticcall(
                    gas(),
                    6,
                    add(input, add(start, 0x20)),
                    0x80,
                    add(input, start),
                    0x40
                )
            }
            require(ret);
        }
    }

    function ecc_mul(
        uint256[] memory input,
        uint256 offset
    ) internal view {
        return msm(input, offset, 1);
    }

    function ecc_mul_add(
        uint256[] memory input,
        uint256 offset
    ) internal view {
        bool ret = false;
        uint256 p1 = offset * 0x20 + 0x20;
        uint256 p2 = p1 + 0x40;

        assembly {
            ret := staticcall(
                gas(),
                7,
                add(input, p2),
                0x60,
                add(input, p2),
                0x40
            )
        }
        require(ret);

        assembly {
            ret := staticcall(
                gas(),
                6,
                add(input, p1),
                0x80,
                add(input, p1),
                0x40
            )
        }
        require(ret);
    }

    function fr_pow(uint256 a, uint256 power) internal view returns (uint256) {
        uint256[6] memory input;
        uint256[1] memory result;
        bool ret;

        input[0] = 32;
        input[1] = 32;
        input[2] = 32;
        input[3] = a;
        input[4] = power;
        input[5] = p_mod;

        assembly {
            ret := staticcall(gas(), 0x05, input, 0xc0, result, 0x20)
        }
        require(ret);

        return result[0];
    }

    function fr_mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, p_mod);
    }

    function fr_add(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, b, p_mod);
    }

    function fr_sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, p_mod - b, p_mod);
    }

    function fr_div(uint256 a, uint256 b, uint256 aux) internal pure returns (uint256) {
        uint256 r = mulmod(b, aux, p_mod);
        require(a == r, "div fail");
        require(b != 0, "div zero");
        return aux % p_mod;
    }
}
