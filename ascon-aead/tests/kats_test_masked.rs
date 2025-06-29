// Copyright 2022 Sebastian Ramacher
// SPDX-License-Identifier: Apache-2.0 OR MIT

use ascon_aead::{
    aead::{Aead, AeadInPlace, KeyInit, Payload},
    Key, MaskedAscon128, Nonce,
};
use hex_literal::hex;

fn run_tv<A: KeyInit + AeadInPlace>(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: &[u8],
    ciphertext: &[u8],
) {
    let core = A::new(Key::<A>::from_slice(key));
    let ctxt = core
        .encrypt(
            Nonce::<A>::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .expect("Successful encryption");
    assert_eq!(ctxt, ciphertext);

    let ptxt = core
        .decrypt(
            Nonce::<A>::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .expect("Successful decryption");
    assert_eq!(ptxt, plaintext);
}

#[test]
fn test_maskedascon128_1() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!(""),
        &hex!("E355159F292911F794CB1432A0103A8A"),
    )
}

#[test]
fn test_maskedascon128_2() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("00"),
        &hex!("944DF887CD4901614C5DEDBC42FC0DA0"),
    )
}

#[test]
fn test_maskedascon128_3() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("0001"),
        &hex!("CE1936FBDD191058DEA8769B79319858"),
    )
}

#[test]
fn test_maskedascon128_4() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102"),
        &hex!("4C9450689BE3D7C23925A4219DE6B50C"),
    )
}

#[test]
fn test_maskedascon128_5() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("00010203"),
        &hex!("082389C8819A82BD98C04A3C64A63AA9"),
    )
}

#[test]
fn test_maskedascon128_6() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("0001020304"),
        &hex!("A88AF3E37EE0188B2B70A74BE1AB573F"),
    )
}

#[test]
fn test_maskedascon128_7() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405"),
        &hex!("4700E8F2474520FCE1DF779B496A3D43"),
    )
}

#[test]
fn test_maskedascon128_8() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("00010203040506"),
        &hex!("8CA228C9EA549C73A8BA27291FED88BF"),
    )
}

#[test]
fn test_maskedascon128_9() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("0001020304050607"),
        &hex!("E3DCF95F869752F61CD7A2DB895F918E"),
    )
}

#[test]
fn test_maskedascon128_10() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708"),
        &hex!("ABCDB317ECCFE67A62CF70AE974C3DBE"),
    )
}

#[test]
fn test_maskedascon128_11() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("00010203040506070809"),
        &hex!("4B006A400B6DFB9777BC3446C2B7DC26"),
    )
}

#[test]
fn test_maskedascon128_12() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A"),
        &hex!("D72C225D6BC2075163BED863186EC886"),
    )
}

#[test]
fn test_maskedascon128_13() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B"),
        &hex!("4ACECAA3B349728E7317D82467B2749E"),
    )
}

#[test]
fn test_maskedascon128_14() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C"),
        &hex!("BB6EC1A7AE8120CAD76566397C9AE920"),
    )
}

#[test]
fn test_maskedascon128_15() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("3078530D228A443D764648F498C26CC2"),
    )
}

#[test]
fn test_maskedascon128_16() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("7E4371F17406D6E5328473177A791CEE"),
    )
}

#[test]
fn test_maskedascon128_17() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("EF5763E75FE32F96D7863410FF0B4786"),
    )
}

#[test]
fn test_maskedascon128_18() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("79AC0FA2BF3859D6962D0C0AF45B1D3E"),
    )
}

#[test]
fn test_maskedascon128_19() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("F56840B36DEE4F7D3450762B209CD93C"),
    )
}

#[test]
fn test_maskedascon128_20() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("4A55B63A5F9218829D81973135D03B10"),
    )
}

#[test]
fn test_maskedascon128_21() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("0B1C94E36D55C29951A74FA7E7F7349B"),
    )
}

#[test]
fn test_maskedascon128_22() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("553E4F9A468A134AF718698FDF7144C1"),
    )
}

#[test]
fn test_maskedascon128_23() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("044DFCDDD0AD865B8730D36FB7F4DFF4"),
    )
}

#[test]
fn test_maskedascon128_24() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("0FF1AEF36526F368B9863D668BA72C8A"),
    )
}

#[test]
fn test_maskedascon128_25() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("4946E5D112779DBCB4FE5E8640D9DC6F"),
    )
}

#[test]
fn test_maskedascon128_26() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("C60AF01FDF64346D9AA8D55F19515FF0"),
    )
}

#[test]
fn test_maskedascon128_27() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("B86842A393129CFEA8DBD9C2BC2AAC45"),
    )
}

#[test]
fn test_maskedascon128_28() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("F94421B4A91423877CF6287F71C8848B"),
    )
}

#[test]
fn test_maskedascon128_29() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("CBF0E4425354BFCD970AE960AD908226"),
    )
}

#[test]
fn test_maskedascon128_30() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("D53624C5DC17242BD996122B3637950E"),
    )
}

#[test]
fn test_maskedascon128_31() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("86F389704159260B45A2246A7D9A5B4E"),
    )
}

#[test]
fn test_maskedascon128_32() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("20CB43574F9F5394F3BEB20CEC8D5CC3"),
    )
}

#[test]
fn test_maskedascon128_33() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("8C74C569E1220E9FE403926E5F9B8956"),
    )
}

#[test]
fn test_maskedascon128_34() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!(""),
        &hex!("BC18C3F4E39ECA7222490D967C79BFFC92"),
    )
}

#[test]
fn test_maskedascon128_35() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("00"),
        &hex!("BD4102B707775C3C155AE497B43BF834E5"),
    )
}

#[test]
fn test_maskedascon128_36() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("0001"),
        &hex!("6E4FEE510F556CFE0938D0EB329BB10242"),
    )
}

#[test]
fn test_maskedascon128_37() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102"),
        &hex!("F11F4103B3CAE0C206E65613D9CB6B167B"),
    )
}

#[test]
fn test_maskedascon128_38() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("00010203"),
        &hex!("77AF1DB0843C917B04FF3CCFB1F76AFD65"),
    )
}

#[test]
fn test_maskedascon128_39() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("0001020304"),
        &hex!("0EE7F0711F6A2554D9083B1384DAB75D0E"),
    )
}

#[test]
fn test_maskedascon128_40() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405"),
        &hex!("5B124B8B390FF024F774132EE0557EEB22"),
    )
}

#[test]
fn test_maskedascon128_41() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("00010203040506"),
        &hex!("2E06F902CE92C84F95656CBBA55F100FCB"),
    )
}

#[test]
fn test_maskedascon128_42() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("0001020304050607"),
        &hex!("695A8F1BD29D59C5C82021B6CACE80C895"),
    )
}

#[test]
fn test_maskedascon128_43() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708"),
        &hex!("320A1C6BADBED598950957A57915001E84"),
    )
}

#[test]
fn test_maskedascon128_44() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("00010203040506070809"),
        &hex!("3D94512CB8F731A4BDE76BC7A605D7A518"),
    )
}

#[test]
fn test_maskedascon128_45() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A"),
        &hex!("76F5EE3B934FC1E91255EB17CEBFF1E191"),
    )
}

#[test]
fn test_maskedascon128_46() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B"),
        &hex!("5904DD9D046F222322BA4D15FDFD3E5036"),
    )
}

#[test]
fn test_maskedascon128_47() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("84A39968C83395166A1A2995B890734EB8"),
    )
}

#[test]
fn test_maskedascon128_48() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E4BD57543272C1F745559FCD32A6F0F95"),
    )
}

#[test]
fn test_maskedascon128_49() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E49CB3747677963E37F9F298EECA35300"),
    )
}

#[test]
fn test_maskedascon128_50() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE4C30EAE829E2C5569A1D688C2616AEE"),
    )
}

#[test]
fn test_maskedascon128_51() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("86D1F8C7161F1D833B98DB88606A9776A7"),
    )
}

#[test]
fn test_maskedascon128_52() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("774911D56576A4A923553F3DF5EB16C5C7"),
    )
}

#[test]
fn test_maskedascon128_53() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D3B95AA2A80F63D23F93E2968806AEEE85"),
    )
}

#[test]
fn test_maskedascon128_54() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A37D44820FFE19D8C5ECA1E9D3972F4A27"),
    )
}

#[test]
fn test_maskedascon128_55() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74348C6460F114F835F7A7900C0A5B6E2E"),
    )
}

#[test]
fn test_maskedascon128_56() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADF005739016CB736E89488358DAF3385B"),
    )
}

#[test]
fn test_maskedascon128_57() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B6F239F6BEBE53AE3BF822D6F3E9C9A46"),
    )
}

#[test]
fn test_maskedascon128_58() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("743BCBA716F2D586F0AB769038E7863FE2"),
    )
}

#[test]
fn test_maskedascon128_59() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("29F665B4CB0E3CC8FD09970E807C0BF751"),
    )
}

#[test]
fn test_maskedascon128_60() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D20EECE849348696C0D3D75EC669674E5"),
    )
}

#[test]
fn test_maskedascon128_61() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("313A73236DE452F3362662F1026B25D591"),
    )
}

#[test]
fn test_maskedascon128_62() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C7295CE46DC9AEDBC2D135AD19C11F80E8"),
    )
}

#[test]
fn test_maskedascon128_63() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3B629A85B6C06BAB88E1ADC34F0C17C869"),
    )
}

#[test]
fn test_maskedascon128_64() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("27ADAA55348693E99A1DF867424CF410B7"),
    )
}

#[test]
fn test_maskedascon128_65() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D67BC10265FF34109B42AD8842A0B314A4"),
    )
}

#[test]
fn test_maskedascon128_66() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B953BF48496164CD10B79FDFA1FF635659"),
    )
}

#[test]
fn test_maskedascon128_67() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!(""),
        &hex!("BC82D5BDE868F7494F57D81E06FACBF70CE1"),
    )
}

#[test]
fn test_maskedascon128_68() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("00"),
        &hex!("BD465B2F5E3ABE7949BFD03CC4D6AC14CFBC"),
    )
}

#[test]
fn test_maskedascon128_69() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("0001"),
        &hex!("6E9F373C0B74264C1CE4D705D995915FCCCD"),
    )
}

#[test]
fn test_maskedascon128_70() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102"),
        &hex!("F19D592CE15098B027CFA76577257FA321D2"),
    )
}

#[test]
fn test_maskedascon128_71() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("00010203"),
        &hex!("7763DA1444516D7DA602C03A073A589A5770"),
    )
}

#[test]
fn test_maskedascon128_72() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("0001020304"),
        &hex!("0E6AB4E7DBA0DD30A57BA83CDE1877D2891B"),
    )
}

#[test]
fn test_maskedascon128_73() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405"),
        &hex!("5B51067DDA396A46D9F738F502F039525FF8"),
    )
}

#[test]
fn test_maskedascon128_74() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("00010203040506"),
        &hex!("2E5B03CD2370A536FBDA43D2DB1F58B6306A"),
    )
}

#[test]
fn test_maskedascon128_75() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("0001020304050607"),
        &hex!("69FF0CC8598FD6CBA54708587A3B96D8AFE7"),
    )
}

#[test]
fn test_maskedascon128_76() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708"),
        &hex!("3225A36E8F3C2F4886EEF6AA906AAB01930E"),
    )
}

#[test]
fn test_maskedascon128_77() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("00010203040506070809"),
        &hex!("3DDC1C1BE21FA7342D28583BD229CBF8D0A4"),
    )
}

#[test]
fn test_maskedascon128_78() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A"),
        &hex!("7680B9FB9FBCF8B3822329B0B27D6B775B6F"),
    )
}

#[test]
fn test_maskedascon128_79() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3AEAB0ABFEC41C833C3EC0FCD2403718B"),
    )
}

#[test]
fn test_maskedascon128_80() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462A08C11B3C690623D447B6D9704E4B705"),
    )
}

#[test]
fn test_maskedascon128_81() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E32A608854A3AF4A69194369815E416323D"),
    )
}

#[test]
fn test_maskedascon128_82() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83BE6F6B4E093BE3083BF3DA9F8553C9F0"),
    )
}

#[test]
fn test_maskedascon128_83() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE3C82E16CD8C3957966B6EBD167213A483"),
    )
}

#[test]
fn test_maskedascon128_84() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684919DA2D79C1AC1B52D05B68DF35C8F7A"),
    )
}

#[test]
fn test_maskedascon128_85() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA2ABC3EB9D571FB53D1B7C9091BA65C91"),
    )
}

#[test]
fn test_maskedascon128_86() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323956DE8BA617631352060BCAC573F120D"),
    )
}

#[test]
fn test_maskedascon128_87() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31A62E94A4891CBBF0EE8E2DB6126F46C5E"),
    )
}

#[test]
fn test_maskedascon128_88() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA328F8F3940E53EF780013D6C12A8B2F4"),
    )
}

#[test]
fn test_maskedascon128_89() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB9F7E42EFA8EB4A109007C80027FFE128"),
    )
}

#[test]
fn test_maskedascon128_90() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29B6FAFC39BB00037532B10835B86E15BD"),
    )
}

#[test]
fn test_maskedascon128_91() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A67E43F8002BD8026CA4DC83646F6D85D7"),
    )
}

#[test]
fn test_maskedascon128_92() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("297075AA4F4B732E57F99994B5476E1581FE"),
    )
}

#[test]
fn test_maskedascon128_93() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D13B2D4B1CC1A582E955B1D513E7DE3C594"),
    )
}

#[test]
fn test_maskedascon128_94() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("3168121DE378E6C65F6CB589FC8C6DDC9621"),
    )
}

#[test]
fn test_maskedascon128_95() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780AEB12057EFD87BA84C90DA11D11394F8"),
    )
}

#[test]
fn test_maskedascon128_96() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2FF9A184339F2E05C29E062FFE306B1BB"),
    )
}

#[test]
fn test_maskedascon128_97() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D16CB7BFBBBCB3CCA5B9F9EE88F7EE241"),
    )
}

#[test]
fn test_maskedascon128_98() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D6701098EE931AF60640FC51AB794F3AE8E9"),
    )
}

#[test]
fn test_maskedascon128_99() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C9344C81E99D0739B198B1E19C513EE41"),
    )
}

#[test]
fn test_maskedascon128_100() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!(""),
        &hex!("BC820D5BCA14147915031C69F6B27848A7EE29"),
    )
}

#[test]
fn test_maskedascon128_101() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("00"),
        &hex!("BD46409C17E4EF8246FEB21B629D2D34ED97A0"),
    )
}

#[test]
fn test_maskedascon128_102() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("0001"),
        &hex!("6E9F82777B23D17A1AFA16EE6BE52B37A47BCE"),
    )
}

#[test]
fn test_maskedascon128_103() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102"),
        &hex!("F19D28312F928677703FEA1614F57D9FD0D7BD"),
    )
}

#[test]
fn test_maskedascon128_104() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("00010203"),
        &hex!("7763F8A2BBFBB05B3B4F54DA1576A863B47409"),
    )
}

#[test]
fn test_maskedascon128_105() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("0001020304"),
        &hex!("0E6A8B1DCAAF912BF13500EEA1B227034DF060"),
    )
}

#[test]
fn test_maskedascon128_106() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405"),
        &hex!("5B51357C0EA9127BC3D256A9D60BEDE8EFD2E6"),
    )
}

#[test]
fn test_maskedascon128_107() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("00010203040506"),
        &hex!("2E5BBAB4BAE525B1CE1100CDBDCB4ED23E89B1"),
    )
}

#[test]
fn test_maskedascon128_108() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("0001020304050607"),
        &hex!("69FFEEBA5F80F8CBDB27F8FB4618473B7C18DD"),
    )
}

#[test]
fn test_maskedascon128_109() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708"),
        &hex!("3225020CFF6C9660BF5C3F03860FE114532049"),
    )
}

#[test]
fn test_maskedascon128_110() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4E7CD32A21A86EA2CDFCCD7A1DEC41A13"),
    )
}

#[test]
fn test_maskedascon128_111() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A"),
        &hex!("76807B647A02193083052D75998B9DCE8EEF6D"),
    )
}

#[test]
fn test_maskedascon128_112() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A50F6A35BF813C68752BF2E504FAB1968E"),
    )
}

#[test]
fn test_maskedascon128_113() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C348424E1C11003F35D340FCC3240B23E4"),
    )
}

#[test]
fn test_maskedascon128_114() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E3253450ED5EA4764A43E7A6BB83748D21E65"),
    )
}

#[test]
fn test_maskedascon128_115() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC7E16F911FB9290AC5F17C40F52E7150E"),
    )
}

#[test]
fn test_maskedascon128_116() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34121DD630A1F15DFEF25D8EFEDE3A13F09"),
    )
}

#[test]
fn test_maskedascon128_117() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("86845314ED19E9DB81F536D26696A5133F3E2C"),
    )
}

#[test]
fn test_maskedascon128_118() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA51436CF960790EB07DAB08E2F20FD4F93C"),
    )
}

#[test]
fn test_maskedascon128_119() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863569EFD8E8FA18695CE3B22D3AA4E263"),
    )
}

#[test]
fn test_maskedascon128_120() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9C2623B07A0C365A72149BD5D206E6C57"),
    )
}

#[test]
fn test_maskedascon128_121() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BAD85D80B7ADF27386DCC43B891F575BB"),
    )
}

#[test]
fn test_maskedascon128_122() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB72E6E801957BA8689483664660E78A821C"),
    )
}

#[test]
fn test_maskedascon128_123() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29662D855A55A0A9462395A9903570188979"),
    )
}

#[test]
fn test_maskedascon128_124() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A3D8F19DE71E9D421D798EF82E27FE1573"),
    )
}

#[test]
fn test_maskedascon128_125() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5AFFED9B37FC44342DEDCC428E5BC4B3C"),
    )
}

#[test]
fn test_maskedascon128_126() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D05D13E6DEBE8D15BBBAF5CFF51B8F864"),
    )
}

#[test]
fn test_maskedascon128_127() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("3168672E64F723E78EAF5D966906B5986B9B1A"),
    )
}

#[test]
fn test_maskedascon128_128() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780139ECFF41F3E52176DCAF5B7820DA27A73"),
    )
}

#[test]
fn test_maskedascon128_129() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F4523A1534CEB4979B15A8F1638D4C7A68"),
    )
}

#[test]
fn test_maskedascon128_130() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D84AEA6EF6A09C7724783050E337D32DBA5"),
    )
}

#[test]
fn test_maskedascon128_131() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F51E2E53334E3B5294D34F4408ACA0DB21"),
    )
}

#[test]
fn test_maskedascon128_132() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78A72FB2093402948DFF30C4766BEBE53B"),
    )
}

#[test]
fn test_maskedascon128_133() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!(""),
        &hex!("BC820DBD218C5C93E3850E974A3704D1223BDEFB"),
    )
}

#[test]
fn test_maskedascon128_134() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("00"),
        &hex!("BD4640C450DA237D4E2230C3E44ABDF9E78FCFCD"),
    )
}

#[test]
fn test_maskedascon128_135() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("0001"),
        &hex!("6E9F820D598CDD2183B5A91E5E6EE7C8F50BE414"),
    )
}

#[test]
fn test_maskedascon128_136() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102"),
        &hex!("F19D28E0AEEB0F246D9DF6C27FD0DDC624C40DEC"),
    )
}

#[test]
fn test_maskedascon128_137() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("00010203"),
        &hex!("7763F8BA02B1E06BC3F2370DA5B314302543E9D0"),
    )
}

#[test]
fn test_maskedascon128_138() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CF463C097AB2FC471431E859AA8C9DB40"),
    )
}

#[test]
fn test_maskedascon128_139() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405"),
        &hex!("5B51354619693D08DC1A49E3A9223910A1B5136A"),
    )
}

#[test]
fn test_maskedascon128_140() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9739CCC2C2692410363AF188BAC59FFF"),
    )
}

#[test]
fn test_maskedascon128_141() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F62957813F82C9CBF53F1E9C0D2EF98B2"),
    )
}

#[test]
fn test_maskedascon128_142() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708"),
        &hex!("322502650E11DE1CB2B66720A5FAA6F0BF48E21E"),
    )
}

#[test]
fn test_maskedascon128_143() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DE9E5F06E7C42C8896DFA938A58F177BFB"),
    )
}

#[test]
fn test_maskedascon128_144() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6431D0A2853C5CA0833476B83953A0E080"),
    )
}

#[test]
fn test_maskedascon128_145() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A53380D335C2430069E95322C536A9BD29B0"),
    )
}

#[test]
fn test_maskedascon128_146() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C3768F65190F371C6D2214F07A5807ED8D8D"),
    )
}

#[test]
fn test_maskedascon128_147() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E32534016306B3632E41A7D57F14301578F5AF6"),
    )
}

#[test]
fn test_maskedascon128_148() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36C2952ACC49B20EDA26983D6C0F450690"),
    )
}

#[test]
fn test_maskedascon128_149() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE341250AC282B59324053C701FE5D0CF777784"),
    )
}

#[test]
fn test_maskedascon128_150() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A83298C48E915F044E663728C887526E6"),
    )
}

#[test]
fn test_maskedascon128_151() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA5111E87B986DE8C14A2CBD1D7F0AF8EA6AC5"),
    )
}

#[test]
fn test_maskedascon128_152() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E70606ECC0042151B6DC2DACAD650E8B8"),
    )
}

#[test]
fn test_maskedascon128_153() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1A870D59A89517C2B8433E46D407A97BC"),
    )
}

#[test]
fn test_maskedascon128_154() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA21ECAC8331A4B1C236F1F12EC0D856D25"),
    )
}

#[test]
fn test_maskedascon128_155() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720CEA24641AD48C8D98531712287D2C97E8"),
    )
}

#[test]
fn test_maskedascon128_156() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B2966936291B842CC7A956D052119942669DC1A"),
    )
}

#[test]
fn test_maskedascon128_157() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39DC6CD71BE8E220D45B9419D63E9617BD9"),
    )
}

#[test]
fn test_maskedascon128_158() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D348F415C36751ADD7EA2BA8C37614BEC2"),
    )
}

#[test]
fn test_maskedascon128_159() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DEBAA54A45D06CB03A23ECB826751EC09"),
    )
}

#[test]
fn test_maskedascon128_160() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("316867253765AB1C494C3B685A3E71A98D477E08"),
    )
}

#[test]
fn test_maskedascon128_161() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C78013587F7AEC07C59EC897CF3D7CB716F9519D"),
    )
}

#[test]
fn test_maskedascon128_162() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45C8886EBA3AC1EE7D28DD5E8877860B37B"),
    )
}

#[test]
fn test_maskedascon128_163() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846FE13DCF55D2A9AF1CB1622DB49AA7BF08"),
    )
}

#[test]
fn test_maskedascon128_164() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A411AC3F7D0215703A80A5FDD9503533E3"),
    )
}

#[test]
fn test_maskedascon128_165() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78650A9A122CF59C591659E212455E1C621E"),
    )
}

#[test]
fn test_maskedascon128_166() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!(""),
        &hex!("BC820DBDF746AB3CAAB87DF290F7ED9BF707E3C4D1"),
    )
}

#[test]
fn test_maskedascon128_167() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("00"),
        &hex!("BD4640C4DA8A7040DA0FEE79264154AC89D2125933"),
    )
}

#[test]
fn test_maskedascon128_168() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("0001"),
        &hex!("6E9F820D5426813AF66BCB94B61768B42B0D06E776"),
    )
}

#[test]
fn test_maskedascon128_169() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102"),
        &hex!("F19D28E0F22C30CFFE614999C82DB62261F776444A"),
    )
}

#[test]
fn test_maskedascon128_170() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("00010203"),
        &hex!("7763F8BA6CFB34138F158D9FCCAF95E2F784F2D300"),
    )
}

#[test]
fn test_maskedascon128_171() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA5F31AF8E948A715B8C431DEC208C0F9C8"),
    )
}

#[test]
fn test_maskedascon128_172() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405"),
        &hex!("5B513546B1EA455C350956CF0AE421A31785B76A45"),
    )
}

#[test]
fn test_maskedascon128_173() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE95F515F015EA179D164B06A53CDFDE0FC8"),
    )
}

#[test]
fn test_maskedascon128_174() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5596EED35BA83999E2948195334F649B0B"),
    )
}

#[test]
fn test_maskedascon128_175() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708"),
        &hex!("322502659958040685DDA566144CCCA1994A222DAB"),
    )
}

#[test]
fn test_maskedascon128_176() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEAB1D356DF6D9C5193AE5CFE49FAE09DD8E"),
    )
}

#[test]
fn test_maskedascon128_177() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A"),
        &hex!("76807B64489CDD2ACBD609E5F65C1D38B2BCADBC5C"),
    )
}

#[test]
fn test_maskedascon128_178() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CFE80D5DA72623A5C23AD0095DB603CCE"),
    )
}

#[test]
fn test_maskedascon128_179() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C0B3A017DD613600EE03481F25B65DF24D"),
    )
}

#[test]
fn test_maskedascon128_180() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF5C7CF94D2515DE04C4DDA437204C1360"),
    )
}

#[test]
fn test_maskedascon128_181() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F002DDA9C556344C1E0836E3E86E8C9D84"),
    )
}

#[test]
fn test_maskedascon128_182() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FD2B51E8AE5F3CBBE843194A56F3380160"),
    )
}

#[test]
fn test_maskedascon128_183() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FFAD728CE0C193FB75CB944C151F4E27D"),
    )
}

#[test]
fn test_maskedascon128_184() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159A007F0DB5BF7CC1B72FB94BE92442088"),
    )
}

#[test]
fn test_maskedascon128_185() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E59F95C5A8EDD36174DD2C32B72BEE4C76A"),
    )
}

#[test]
fn test_maskedascon128_186() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4C49AE8C5DFD36E822F232A13240D7394"),
    )
}

#[test]
fn test_maskedascon128_187() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2632CDA8261E579172DC6F9DE2047F9440E"),
    )
}

#[test]
fn test_maskedascon128_188() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D356CAD7BA58E3D67A493460D4BAA0BBA"),
    )
}

#[test]
fn test_maskedascon128_189() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B296693950C9941956C2B4EC5ECB74476CC0C30D4"),
    )
}

#[test]
fn test_maskedascon128_190() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A20B81DF190BB7FEFADE185DF9FB6DD5F"),
    )
}

#[test]
fn test_maskedascon128_191() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DC692DE758B3CBDEFF640ED88833E0115C"),
    )
}

#[test]
fn test_maskedascon128_192() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE9406773EE2D98BA8EF80FA1F0F525F7E8"),
    )
}

#[test]
fn test_maskedascon128_193() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B4F63F18D9A4FA55806F41AFD716BED236"),
    )
}

#[test]
fn test_maskedascon128_194() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C7801358376A661ED1A918C6D88B36F94F726FC489"),
    )
}

#[test]
fn test_maskedascon128_195() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE9144B39BDAB0043AB3E26DF7CAE22F39C"),
    )
}

#[test]
fn test_maskedascon128_196() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99BF2E18B408692C305149810F5AB181C3"),
    )
}

#[test]
fn test_maskedascon128_197() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44901D4D6F45E224FF57369445A3D27E6DA"),
    )
}

#[test]
fn test_maskedascon128_198() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B2E0A3CBC4B4ACC98994F14B3D87BCD89"),
    )
}

#[test]
fn test_maskedascon128_199() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!(""),
        &hex!("BC820DBDF7A40AE9AF4985E97254DAF329422C950FAD"),
    )
}

#[test]
fn test_maskedascon128_200() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("00"),
        &hex!("BD4640C4DA2F78D6EA93E816CB39E0A80B4DCCE94BFC"),
    )
}

#[test]
fn test_maskedascon128_201() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("0001"),
        &hex!("6E9F820D5468D9E5E408FCE9EC15C85B38CCEFEBD120"),
    )
}

#[test]
fn test_maskedascon128_202() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102"),
        &hex!("F19D28E0F2224DEE285B29A1342E13F600F333E97113"),
    )
}

#[test]
fn test_maskedascon128_203() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE936102D7B46CA8704612D627AC16E5944"),
    )
}

#[test]
fn test_maskedascon128_204() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA5177A53CB9F906EA699850B741C89B24A4E"),
    )
}

#[test]
fn test_maskedascon128_205() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1AE7318B7D7269A8D9204C83726A1F50D"),
    )
}

#[test]
fn test_maskedascon128_206() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599A512FD6008CE2A1966B8C0DC55BF3F9E"),
    )
}

#[test]
fn test_maskedascon128_207() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505362C165AC93A2C5BB9368249E9C6D6F1"),
    )
}

#[test]
fn test_maskedascon128_208() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCAB45922B2F7E244FBADF133386563564"),
    )
}

#[test]
fn test_maskedascon128_209() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF17462F354D4BB4CA64ABAFECE5DFB3201"),
    )
}

#[test]
fn test_maskedascon128_210() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A"),
        &hex!("76807B644889F84B8161C60383A1BD471FDC895865A6"),
    )
}

#[test]
fn test_maskedascon128_211() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD1E048B8615DAE0AE2DC34D89722C68571"),
    )
}

#[test]
fn test_maskedascon128_212() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06A4D42989455385C2B38E502240479371E"),
    )
}

#[test]
fn test_maskedascon128_213() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7F397440F3EC770E3D3BFEA60030241A79"),
    )
}

#[test]
fn test_maskedascon128_214() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088CC3FF6D959ACE12378B25FCF9556C471"),
    )
}

#[test]
fn test_maskedascon128_215() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA3FF82356F5ABEFDC4023D85E704A2D6A"),
    )
}

#[test]
fn test_maskedascon128_216() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFC8C43E178395D2990DFAD13F96961D4F"),
    )
}

#[test]
fn test_maskedascon128_217() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA51115962859C7AAF78D33DE639B520C99B976930"),
    )
}

#[test]
fn test_maskedascon128_218() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E59725809A1E053BB8807583793861DB825AD"),
    )
}

#[test]
fn test_maskedascon128_219() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D1B1E0F4A0494802543525A9A51DBB06BB"),
    )
}

#[test]
fn test_maskedascon128_220() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635D4E5AB26FB3C916E53398868BF92D6E67"),
    )
}

#[test]
fn test_maskedascon128_221() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D411804EA822D0EAFB27D1D82F240B1E1B6"),
    )
}

#[test]
fn test_maskedascon128_222() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DACA00ABA0D73DA3EC8666D1E05380DB39"),
    )
}

#[test]
fn test_maskedascon128_223() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A51ABBE26927BBD19A417FFEA00FD0936C6"),
    )
}

#[test]
fn test_maskedascon128_224() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDE1037A382DCB83E6F5D0DB387AE072C6F"),
    )
}

#[test]
fn test_maskedascon128_225() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE99448A9D9F23DE84D5620AA3885710F479A"),
    )
}

#[test]
fn test_maskedascon128_226() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA2932B77276DF6916AB2E3D4EE3BA294"),
    )
}

#[test]
fn test_maskedascon128_227() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C78013583721B474CD093BE0C36353BE2CC87DD24AEA"),
    )
}

#[test]
fn test_maskedascon128_228() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E7A4A740BE0693EE435EBBA9F0B632996"),
    )
}

#[test]
fn test_maskedascon128_229() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F9917E1447E30F742B782E1BBCEF2E0EA28FD"),
    )
}

#[test]
fn test_maskedascon128_230() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A449717E7E2589C8D1CB8D5BB599D02CC4BF7A"),
    )
}

#[test]
fn test_maskedascon128_231() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B622AB3CEF82D4964388EE6ACA28391C9F6"),
    )
}

#[test]
fn test_maskedascon128_232() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!(""),
        &hex!("BC820DBDF7A463CE9985966C40BC56A9C5180E23F7086C"),
    )
}

#[test]
fn test_maskedascon128_233() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA03B74F698C695A740DE9F8B9C060CCE3"),
    )
}

#[test]
fn test_maskedascon128_234() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("0001"),
        &hex!("6E9F820D5468A026F06AB25F39569E8731B103543DFB8F"),
    )
}

#[test]
fn test_maskedascon128_235() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3943721E28BE3BCFB19BD17A072021F00"),
    )
}

#[test]
fn test_maskedascon128_236() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91E3F511196C8AC4E6FB3C7462B63F2F2B5"),
    )
}

#[test]
fn test_maskedascon128_237() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F59CC32E96F262D3AFEB4C0E23F182AC7F"),
    )
}

#[test]
fn test_maskedascon128_238() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DCC6CA9DB502F91797830C5A1C14769134"),
    )
}

#[test]
fn test_maskedascon128_239() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC69715FB4556DECD1D4D4834EA4923C12"),
    )
}

#[test]
fn test_maskedascon128_240() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4314219112BF5A163EA5D73EB778848BE"),
    )
}

#[test]
fn test_maskedascon128_241() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4EF4D546056A658769D6E6A3FE44FB086"),
    )
}

#[test]
fn test_maskedascon128_242() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18B6C7F9B6614818FAD0C0BFAC6CF492D14"),
    )
}

#[test]
fn test_maskedascon128_243() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896C28CA17ED47E1FC9CA44989BE3F2D289D"),
    )
}

#[test]
fn test_maskedascon128_244() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD1715ACD899DF853EF95823F7EAE375E1A53"),
    )
}

#[test]
fn test_maskedascon128_245() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE42216973BB8F4CB76E6C56C0A8CDC79C"),
    )
}

#[test]
fn test_maskedascon128_246() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0EE23D55AE0C820645AA502B3FE988D81"),
    )
}

#[test]
fn test_maskedascon128_247() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088234C11CFC6D934D1970C550C6A4CEE177B"),
    )
}

#[test]
fn test_maskedascon128_248() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA170AF0C57E1ECB24B13703B4074FFDA82C"),
    )
}

#[test]
fn test_maskedascon128_249() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF96A10554F2BA496365CA9EC83456635F2"),
    )
}

#[test]
fn test_maskedascon128_250() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627CB07AFAF2698955EB1D0B46AC4B0C7504"),
    )
}

#[test]
fn test_maskedascon128_251() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E5972978CB4BB85FE34179D82DBA9C4729956A9"),
    )
}

#[test]
fn test_maskedascon128_252() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D182D920FA34B3206B2854EAAA24AF3529A6"),
    )
}

#[test]
fn test_maskedascon128_253() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCB926B6136EF4B6C05D286D90ACE512746"),
    )
}

#[test]
fn test_maskedascon128_254() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EC811279250DE19710B465C790CC9E951"),
    )
}

#[test]
fn test_maskedascon128_255() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8CDBBD3BC5836550023B74915FA9CBAAD"),
    )
}

#[test]
fn test_maskedascon128_256() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A5129E86EF92E6486D298AAA87FE6FE3BF96D"),
    )
}

#[test]
fn test_maskedascon128_257() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED1846E7B60E9BFC21726DDF5D08B1606A3"),
    )
}

#[test]
fn test_maskedascon128_258() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEBD465D327D1BC6D5CDFDD844C01A2E39"),
    )
}

#[test]
fn test_maskedascon128_259() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA9D159293987DB6EC695CA593CE1F865D8"),
    )
}

#[test]
fn test_maskedascon128_260() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C2BEE39663B98EE1649BA3089623F6E9A"),
    )
}

#[test]
fn test_maskedascon128_261() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F2C8ECCA953D1655614E1DF15F13AB7DC"),
    )
}

#[test]
fn test_maskedascon128_262() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F991733756D10D1544B33FC9E8BF0E7870CE3D0"),
    )
}

#[test]
fn test_maskedascon128_263() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE19AD2F6E65DCC0087F195AC3AFB87AA8"),
    )
}

#[test]
fn test_maskedascon128_264() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246F02CDD89EE300146CA89CC41558474B0"),
    )
}

#[test]
fn test_maskedascon128_265() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C01A8807A44254B42AC6BB490DA1E000A"),
    )
}

#[test]
fn test_maskedascon128_266() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA565004C927913485A90B18BE0F3741A393"),
    )
}

#[test]
fn test_maskedascon128_267() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D4479650030FCAD9F01546D91CCCE82F5C"),
    )
}

#[test]
fn test_maskedascon128_268() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFE5857114BF49C50C03B179885C99B370"),
    )
}

#[test]
fn test_maskedascon128_269() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1C2E6D6FA2309EF26D1E6DF20FAEB33A6"),
    )
}

#[test]
fn test_maskedascon128_270() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3CA175AC21A7D27119573A71F04040F1"),
    )
}

#[test]
fn test_maskedascon128_271() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8A17E753A550D508FBCA24A9183E100B01"),
    )
}

#[test]
fn test_maskedascon128_272() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F863B01D95B8945703B3B4A99B5E847A1"),
    )
}

#[test]
fn test_maskedascon128_273() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A489E897E5F141B2E4A2DAD326085A79408A"),
    )
}

#[test]
fn test_maskedascon128_274() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCD056B72EB2EA65EC5A8390501D5307D5"),
    )
}

#[test]
fn test_maskedascon128_275() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBBB2276ED3BC0025CE70E9F9C3ABAC03EB"),
    )
}

#[test]
fn test_maskedascon128_276() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE5BF6CB2C84EF6F0E27EDB1E0C3042758E"),
    )
}

#[test]
fn test_maskedascon128_277() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F9A0092415BF7CBB98FDFC4A4297B1E3E0"),
    )
}

#[test]
fn test_maskedascon128_278() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28CB3C68A035642460945476BE05D40A1E"),
    )
}

#[test]
fn test_maskedascon128_279() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFCD1D00A2AE6CDFD124CC88C69CB5D508"),
    )
}

#[test]
fn test_maskedascon128_280() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A777BF116992B7C3B88403B5DB8DFB50F"),
    )
}

#[test]
fn test_maskedascon128_281() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA1744263AC941C6EDEFB49505018DE9DAC9B3"),
    )
}

#[test]
fn test_maskedascon128_282() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F60A842C859E594D287C37E3CC96D1BB27"),
    )
}

#[test]
fn test_maskedascon128_283() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B4F9E21F048B85228FB7341C0F219898B"),
    )
}

#[test]
fn test_maskedascon128_284() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EA47E8684345C8CCD2F4FE66DF43F14D6C"),
    )
}

#[test]
fn test_maskedascon128_285() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D1822272BBB65A7DC95E7DDEDDCD7E897594FE"),
    )
}

#[test]
fn test_maskedascon128_286() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAAD94C76E59BF92EF72AF4DEFF19E1E121"),
    )
}

#[test]
fn test_maskedascon128_287() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EECD199F3466038201046CD9014E5206156"),
    )
}

#[test]
fn test_maskedascon128_288() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB873D07DEB14119BE886991FC34C7533373C"),
    )
}

#[test]
fn test_maskedascon128_289() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A5129583F067A14D9DFFE298CAFBD5D9B084675"),
    )
}

#[test]
fn test_maskedascon128_290() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18DC4BB79C9A9A48F7BB00808E1AA313387"),
    )
}

#[test]
fn test_maskedascon128_291() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC2A5E625089511B078A2E66D14346147EB"),
    )
}

#[test]
fn test_maskedascon128_292() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA99554EFAB257366A87CB0043C4ED4DACE46"),
    )
}

#[test]
fn test_maskedascon128_293() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C325EAA80F37549500B8785602B54CAEB11"),
    )
}

#[test]
fn test_maskedascon128_294() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F371D6F23757EDC6C010DC34DF6842F6CD2"),
    )
}

#[test]
fn test_maskedascon128_295() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F9917338017F297DD0712D02899570D25D686E23B"),
    )
}

#[test]
fn test_maskedascon128_296() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE131301B9632952ED5D9539C682262EF28F"),
    )
}

#[test]
fn test_maskedascon128_297() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0F4DDFDF86CED08389F0D3A1B58A4882A"),
    )
}

#[test]
fn test_maskedascon128_298() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B46D53803F5D35E0A27D353508C9D054A"),
    )
}

#[test]
fn test_maskedascon128_299() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC8FA8FC61C17487D416BC2500FE08AAD4"),
    )
}

#[test]
fn test_maskedascon128_300() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D4765A7C907A77A3E6757192F0E0B60632B3"),
    )
}

#[test]
fn test_maskedascon128_301() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA3037E9B0B10726BD9C37122136DEA6EB"),
    )
}

#[test]
fn test_maskedascon128_302() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED16864D7B17E30D6B84786DC6E8BF4E4BAF6"),
    )
}

#[test]
fn test_maskedascon128_303() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D375623AC11C852FF0A98098CCB7429F2"),
    )
}

#[test]
fn test_maskedascon128_304() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAA1C99295F2144CF49C8089EE97F28C124"),
    )
}

#[test]
fn test_maskedascon128_305() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D7EA5A5C832E8F41072BD3400FCAD0D64"),
    )
}

#[test]
fn test_maskedascon128_306() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897ECF5BDD353828B5C3B397863CE8BFD719"),
    )
}

#[test]
fn test_maskedascon128_307() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC4E2222006C2A2294B855A474A7BC0C183"),
    )
}

#[test]
fn test_maskedascon128_308() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BBCA82D87B50BC91849B392CE10C92AE1"),
    )
}

#[test]
fn test_maskedascon128_309() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE588A9EDBEC3BF6112310DD58DA04C45D25D"),
    )
}

#[test]
fn test_maskedascon128_310() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D41A5F4500358CFE6C746EA9C00A832C9"),
    )
}

#[test]
fn test_maskedascon128_311() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC0E8002A11357997CAC91CBBF576C1406"),
    )
}

#[test]
fn test_maskedascon128_312() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD237FAD17CC79733643EA0A700A720D892"),
    )
}

#[test]
fn test_maskedascon128_313() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8E104704C8F7BE940187D0A5DDFF69ACF3"),
    )
}

#[test]
fn test_maskedascon128_314() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D2005397035FC67EA1209D61A8FFBE851"),
    )
}

#[test]
fn test_maskedascon128_315() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A823C7312B7CD22838B56833BA5390A96"),
    )
}

#[test]
fn test_maskedascon128_316() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B8565F1B6FAFF78FE04B036FD6E4F440246"),
    )
}

#[test]
fn test_maskedascon128_317() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB5BE7B961574BE4E8F422A2B695A548D08"),
    )
}

#[test]
fn test_maskedascon128_318() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F3AE875E72E80F1B0D6E45D0810D0F737C"),
    )
}

#[test]
fn test_maskedascon128_319() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA405B3525B05D8D68FCD01F7A35FDED0A41"),
    )
}

#[test]
fn test_maskedascon128_320() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45D57012DFC6E1A7493721FE4172066117"),
    )
}

#[test]
fn test_maskedascon128_321() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB87333366F1FE84C2D42364202F331C2D2B75D"),
    )
}

#[test]
fn test_maskedascon128_322() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EED31AC302A6FAC414DE28ECA8E6F37C85"),
    )
}

#[test]
fn test_maskedascon128_323() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D811EE7F2D9BBD55DCE3FFA57F7FFD307B1"),
    )
}

#[test]
fn test_maskedascon128_324() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27EC6B0BD3E896119BD5A7CB2153E2EF6AB"),
    )
}

#[test]
fn test_maskedascon128_325() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FCC3C986EEE5347527C1E7467D27F32829"),
    )
}

#[test]
fn test_maskedascon128_326() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D2326D7FDDB3535A8CCFBF564203081924"),
    )
}

#[test]
fn test_maskedascon128_327() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731883EFFCBC3C7EC8585EDD8FF1CFFF143"),
    )
}

#[test]
fn test_maskedascon128_328() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F991733801941D4D1D0F2760ABE1DA6B85F50C12E46"),
    )
}

#[test]
fn test_maskedascon128_329() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F9681E158D79E3D384374022E4838AE341"),
    )
}

#[test]
fn test_maskedascon128_330() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3CD840D6155C99EB0E4185FE0A0C9DC69"),
    )
}

#[test]
fn test_maskedascon128_331() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B29C9A5A225C5FF2A5358A82D55DC7157AF"),
    )
}

#[test]
fn test_maskedascon128_332() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC7991C3A39392C59631AC91F39AA50FB182"),
    )
}

#[test]
fn test_maskedascon128_333() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476628B3F745CAB219F55F8E39919D9C1E3B6"),
    )
}

#[test]
fn test_maskedascon128_334() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA115DCC8010DCD388868DEB9E72D157B8C0"),
    )
}

#[test]
fn test_maskedascon128_335() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F74C7113AD7BEF7C826D6EFC49C3CC3DB"),
    )
}

#[test]
fn test_maskedascon128_336() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E782C1CAED6E3570D3C167F1C55BAC13"),
    )
}

#[test]
fn test_maskedascon128_337() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA0DDA56A49BCBD3333A2E4D0A4BEB8F0FB"),
    )
}

#[test]
fn test_maskedascon128_338() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D865CFDEA5788E9FD0DDE9F585067078A71"),
    )
}

#[test]
fn test_maskedascon128_339() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC93B4AF37A996A1CDCDD047F83D55553"),
    )
}

#[test]
fn test_maskedascon128_340() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC460B07943861109FA5234CC4C8CC54D6D53"),
    )
}

#[test]
fn test_maskedascon128_341() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4482A823D457BBB0420C6EA3E93469585"),
    )
}

#[test]
fn test_maskedascon128_342() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE5884238A66EC016F8D784690455ED86BCA117"),
    )
}

#[test]
fn test_maskedascon128_343() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D70D58C77698D2C8BAB8B414420BEB88157"),
    )
}

#[test]
fn test_maskedascon128_344() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC18D7AD7E7CB3EF8BCE97016B50940A4199"),
    )
}

#[test]
fn test_maskedascon128_345() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BD2AD1D6DE0798731C94390DFA9E28FB3"),
    )
}

#[test]
fn test_maskedascon128_346() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9E474BCCDF4E296516A64F4FCF9240081"),
    )
}

#[test]
fn test_maskedascon128_347() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01F9E880AA510ED2458873665F0DBD1B8E"),
    )
}

#[test]
fn test_maskedascon128_348() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7AF6FA7C56EAB371F3AA96338D5ADC0FFF"),
    )
}

#[test]
fn test_maskedascon128_349() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E56864D46EEBF9B17A23EF01AC3F6A56D"),
    )
}

#[test]
fn test_maskedascon128_350() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C51596B36FF941A15308E7A975383DD3C"),
    )
}

#[test]
fn test_maskedascon128_351() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332EB5D4E5C5911A8FF1AE7339C9C8A50A1"),
    )
}

#[test]
fn test_maskedascon128_352() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A9836FEB54EA9E1ADAF9343398B027FD9"),
    )
}

#[test]
fn test_maskedascon128_353() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC4597207CF70118EF26DFB95C6D70DBB5167E"),
    )
}

#[test]
fn test_maskedascon128_354() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB87333012117D712567DC1B08E27D24ABE2D9E3F"),
    )
}

#[test]
fn test_maskedascon128_355() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE30BE3A3296E2DC42D698EBBAEDA830DB52"),
    )
}

#[test]
fn test_maskedascon128_356() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD99F1097418AFB6556832039EBB9E1072"),
    )
}

#[test]
fn test_maskedascon128_357() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E63D3466BCE8AF7C325EB6D7BBD94B3C089"),
    )
}

#[test]
fn test_maskedascon128_358() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC474169EE68A64472FAA60B8A8D0B21DD6F"),
    )
}

#[test]
fn test_maskedascon128_359() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20DF1C094AB637441FDB14CE10CBAF4AEB4"),
    )
}

#[test]
fn test_maskedascon128_360() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F373164918FC498FBE952EFED4EDAB63D1809B1"),
    )
}

#[test]
fn test_maskedascon128_361() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F991733801999C2413B9D3A48C3F8D5234E3516E1DBAB"),
    )
}

#[test]
fn test_maskedascon128_362() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BCF73FEE4C7065CDDBDBF672AD48F4F35"),
    )
}

#[test]
fn test_maskedascon128_363() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1D567D22AA1E303C021FC57DE0B9330DD"),
    )
}

#[test]
fn test_maskedascon128_364() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B298802CF2EE93FF523BD068CE507C683116C"),
    )
}

#[test]
fn test_maskedascon128_365() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC79F7E990D6C7EE9287B4A1D8D9B6B9439974"),
    )
}

#[test]
fn test_maskedascon128_366() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476620F29997475DC5B21AED70EE44C34DBB047"),
    )
}

#[test]
fn test_maskedascon128_367() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA11E1F9CAC9105CBC1F976DD9A01830BBDBF9"),
    )
}

#[test]
fn test_maskedascon128_368() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F0105C50FB633147F93027D24D68A66DCAC"),
    )
}

#[test]
fn test_maskedascon128_369() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E1BB13C3845216D9E1BB4643A9DEFA38DA"),
    )
}

#[test]
fn test_maskedascon128_370() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA0106491EE46D3D0E11FDE892A1A9C1926AB"),
    )
}

#[test]
fn test_maskedascon128_371() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D86F95ECEB88A892347749117B946960A465D"),
    )
}

#[test]
fn test_maskedascon128_372() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC8F390480DDDF5C59A313E252A9BF38059"),
    )
}

#[test]
fn test_maskedascon128_373() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC46018B6B900B6EC6204EDB31F2C094AC212C9"),
    )
}

#[test]
fn test_maskedascon128_374() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4EDA2A840B22FA894ABEF9E41D49471E04C"),
    )
}

#[test]
fn test_maskedascon128_375() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE58842CBB4C776E1FC0CDEA268F27171C1636772"),
    )
}

#[test]
fn test_maskedascon128_376() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D708C3F9B4E0E222D8BAFF2A52B044EE3D247"),
    )
}

#[test]
fn test_maskedascon128_377() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC182D586AC943C7C681D63F03ABE78252369D"),
    )
}

#[test]
fn test_maskedascon128_378() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BEC493743A337DB8D1E54203F73BAF51016"),
    )
}

#[test]
fn test_maskedascon128_379() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9BA87C7D9F6BC4A69BEA69225CE0193D737"),
    )
}

#[test]
fn test_maskedascon128_380() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01DA84EC2E553F0AF56E0776164DA35AF72F"),
    )
}

#[test]
fn test_maskedascon128_381() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7A49F682D714B4E306646E6CDB863BD93BC3"),
    )
}

#[test]
fn test_maskedascon128_382() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E679BCBBCDB8903A32B900D0F79DF4900F2"),
    )
}

#[test]
fn test_maskedascon128_383() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C8F22ACF8781069193F582EF6161AAEDC42"),
    )
}

#[test]
fn test_maskedascon128_384() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332F2365556EA34A1D999990F16F51676745B"),
    )
}

#[test]
fn test_maskedascon128_385() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A5C3DCCE0A3CBB0C71FBF8FD07BC5386363"),
    )
}

#[test]
fn test_maskedascon128_386() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45978EF78D100C964E121B55E11D3C57CF61A7"),
    )
}

#[test]
fn test_maskedascon128_387() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8733301D70C583CE3EF4650AF0DE756C61A01A73D"),
    )
}

#[test]
fn test_maskedascon128_388() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE309169F0CC17CF305D1605B657B3F3362D8D"),
    )
}

#[test]
fn test_maskedascon128_389() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD6C7EAA9001747D4197D292AF5DFAEF82CF"),
    )
}

#[test]
fn test_maskedascon128_390() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E631448EB6361367ECE979CE0DECD0301423F"),
    )
}

#[test]
fn test_maskedascon128_391() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC470C0D882B1A7BD480ECB66739C4DCBFCAB1"),
    )
}

#[test]
fn test_maskedascon128_392() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20D3DD0D32AA275FF244C4CD4953F34FAAB4B"),
    )
}

#[test]
fn test_maskedascon128_393() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731641C8672EF1E9530AD6C47C8EFB56B09A32C"),
    )
}

#[test]
fn test_maskedascon128_394() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99173380199972ED28C17572CEF44CD9D930EAD006640D"),
    )
}

#[test]
fn test_maskedascon128_395() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BDDBF85C5C75DE240B593A58105606FED74"),
    )
}

#[test]
fn test_maskedascon128_396() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1A5416169930686EB8DF5D27AC1FCE8154A"),
    )
}

#[test]
fn test_maskedascon128_397() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B29884A7D1C07DC8D0D5ED48E64D7DCB25C325F"),
    )
}

#[test]
fn test_maskedascon128_398() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC79F7FD4A8FCF788F46F3C6A204295009DB94C2"),
    )
}

#[test]
fn test_maskedascon128_399() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476620F584D41DD92D033C684EF05C4D2414DF92F"),
    )
}

#[test]
fn test_maskedascon128_400() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA11E1518AFA8DEA8DD03876AC4D57A3E3796FE1"),
    )
}

#[test]
fn test_maskedascon128_401() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F018AAAAE6426B668C95B845B822166A11D59"),
    )
}

#[test]
fn test_maskedascon128_402() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E1D8E3F114A959F0436C3C4DEFD8B6247829"),
    )
}

#[test]
fn test_maskedascon128_403() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA010DCF29744B9EC718709EAF20E38B7157334"),
    )
}

#[test]
fn test_maskedascon128_404() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D86F9D6200163BCC6E0594E82FEB3772702C451"),
    )
}

#[test]
fn test_maskedascon128_405() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC80C581FF689BBF1A0424213E5706E423F48"),
    )
}

#[test]
fn test_maskedascon128_406() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC4601815248F96E3492EDE5BA9E850B44160A908"),
    )
}

#[test]
fn test_maskedascon128_407() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4EDAC2CE1F87423F05B9627E3206B08EB8FBC"),
    )
}

#[test]
fn test_maskedascon128_408() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE58842CB4A94561BC1596B8E690C1C55263020636B"),
    )
}

#[test]
fn test_maskedascon128_409() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D708C5BCA4E671AC19C875F4199BF8FA872BDDE"),
    )
}

#[test]
fn test_maskedascon128_410() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC182DF69A28E81EEF58D7A1F97714EEBB997795"),
    )
}

#[test]
fn test_maskedascon128_411() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BEC2DCA0E9E49F99C745B78D290FA76840B0B"),
    )
}

#[test]
fn test_maskedascon128_412() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9BAB7601569C112D9BB851B619DCA52B07971"),
    )
}

#[test]
fn test_maskedascon128_413() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01DA8A4FBE0AF7A029E02AC2321ED6B96A0040"),
    )
}

#[test]
fn test_maskedascon128_414() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7A49600A25A3A60C6218002B62B500CD570C10"),
    )
}

#[test]
fn test_maskedascon128_415() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E67F97C1E05DA800A312422BADFF7F52F2685"),
    )
}

#[test]
fn test_maskedascon128_416() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C8F13AEBB5FDB936D0F714CD5CD9A75156CE8"),
    )
}

#[test]
fn test_maskedascon128_417() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332F2459E7087F8D69D9D783EF1DA1E18BC7EB9"),
    )
}

#[test]
fn test_maskedascon128_418() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A5C2406C929C79830B1B3129053FD8E6429BC"),
    )
}

#[test]
fn test_maskedascon128_419() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45978E6F099C93C1A1229F6CA679F47295754175"),
    )
}

#[test]
fn test_maskedascon128_420() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8733301D70F34EE7481F58DABF8DFDD5E029C6ED141"),
    )
}

#[test]
fn test_maskedascon128_421() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE3091493C623AB0EEA65838A7679C86DB353D0F"),
    )
}

#[test]
fn test_maskedascon128_422() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD6C1F96BEFE1CBB58EEC93BBCEF6914ED0550"),
    )
}

#[test]
fn test_maskedascon128_423() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E631448F2C0227FCC1539CEA5BEF561CBEED0AC"),
    )
}

#[test]
fn test_maskedascon128_424() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC470C8F2ADC5376EC061A58D39F77A4ABFAD5E8"),
    )
}

#[test]
fn test_maskedascon128_425() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20D3D7097A290B3CC022F85F1754EB7F7BFC313"),
    )
}

#[test]
fn test_maskedascon128_426() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731641C6E5BCD5D4993978154FDA2E12546FB4D43"),
    )
}

#[test]
fn test_maskedascon128_427() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99173380199972D129B5063BC0552F8D4DAC8C6C17D5DDB5"),
    )
}

#[test]
fn test_maskedascon128_428() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BDD82240E2B921122EE96896BAA7A6724BBDC"),
    )
}

#[test]
fn test_maskedascon128_429() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1A5D3A80A06C0C851CF53DAF1B58948FF2E1E"),
    )
}

#[test]
fn test_maskedascon128_430() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B29884AD62BBF1806B99220D1C7D5C780B6670433"),
    )
}

#[test]
fn test_maskedascon128_431() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC79F7FDD0F5A5FF903850EE458B1412A7325CBEDA"),
    )
}

#[test]
fn test_maskedascon128_432() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476620F5865ED4E3616962BA2BA0FD39997DB92DCB0"),
    )
}

#[test]
fn test_maskedascon128_433() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA11E151538105B64988BDC3199E79C677DAC9C67D"),
    )
}

#[test]
fn test_maskedascon128_434() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F018AB60DA3A4A96C735BEE2FAF2B1BE26A061D"),
    )
}

#[test]
fn test_maskedascon128_435() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E1D8D713F47BA91F8765555D2D8884E8649DE2"),
    )
}

#[test]
fn test_maskedascon128_436() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA010DC49BABB076329398CBE2621CEEABF2D999F"),
    )
}

#[test]
fn test_maskedascon128_437() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D86F9D6516781557A57C6D09F102E1659883B67FF"),
    )
}

#[test]
fn test_maskedascon128_438() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC80CBD4F8B0B89564F14027C497D9222129E85"),
    )
}

#[test]
fn test_maskedascon128_439() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC460181575EB717E219B4939D8B6471FAA9B4A2F14"),
    )
}

#[test]
fn test_maskedascon128_440() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4EDACCEC8B43D6D1F3C38191BE4A57B8B41169B"),
    )
}

#[test]
fn test_maskedascon128_441() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE58842CB4AED3C0254ADF950EBCDB1A9C193420B4157"),
    )
}

#[test]
fn test_maskedascon128_442() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D708C5B11845171502125BA607CCA01D3B3292C41"),
    )
}

#[test]
fn test_maskedascon128_443() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC182DF6B5AD69C8F30A5BA3270DD277999732B64F"),
    )
}

#[test]
fn test_maskedascon128_444() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BEC2D8A2EFDE23D534EBAE541345FBF7566DAA0"),
    )
}

#[test]
fn test_maskedascon128_445() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9BAB74D305CD3549E1F0D14930CFDB168D0F21F"),
    )
}

#[test]
fn test_maskedascon128_446() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01DA8A0EB7C322FA5FBA9BCD32F46521712A3F27"),
    )
}

#[test]
fn test_maskedascon128_447() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7A49601063934BE693EC0C20CB214FB95ADC73AD"),
    )
}

#[test]
fn test_maskedascon128_448() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E67F95B29CCC9FC4F4FCC6267FD49C97BCF567D"),
    )
}

#[test]
fn test_maskedascon128_449() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C8F134D49C8200E44021EA9F41BCD32429BCFA0"),
    )
}

#[test]
fn test_maskedascon128_450() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332F245C7FBD1990862F19C427FB7B09E4E0F280E"),
    )
}

#[test]
fn test_maskedascon128_451() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A5C24E417F24415BFEB68700365FE1CF7FD79C9"),
    )
}

#[test]
fn test_maskedascon128_452() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45978E6F89E78386941A019842B6D85EE4584B95D7"),
    )
}

#[test]
fn test_maskedascon128_453() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8733301D70F21E5AEEA6926F739785C85EF9E20FADF62"),
    )
}

#[test]
fn test_maskedascon128_454() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE309149034D4674D8DB745A6EE3E95A47EBE77764"),
    )
}

#[test]
fn test_maskedascon128_455() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD6C1F6BF08CD1AB628789BB01DA600EA11A6CB3"),
    )
}

#[test]
fn test_maskedascon128_456() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E6314484B0C780A2D13661B515101B4A25B51AFD9"),
    )
}

#[test]
fn test_maskedascon128_457() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC470C8F26D6D701373CDD506C0AB4D3570712723B"),
    )
}

#[test]
fn test_maskedascon128_458() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20D3D705A54FB7AA20660DCDAE94D97B71A6647A6"),
    )
}

#[test]
fn test_maskedascon128_459() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731641C6EC7575C7A8C3FDAC44461027EFB40E1168A"),
    )
}

#[test]
fn test_maskedascon128_460() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99173380199972D19B000DE9A5285AB89A5D80F308FF3EE2D2"),
    )
}

#[test]
fn test_maskedascon128_461() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BDD82E5BBE210FE2257D72FFA56BC12EE47BF39"),
    )
}

#[test]
fn test_maskedascon128_462() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1A5D373020162A0AA7DE86B60A6896EA3A7514C"),
    )
}

#[test]
fn test_maskedascon128_463() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B29884AD69169B166A6441745A77DD0DF6C80BD700C"),
    )
}

#[test]
fn test_maskedascon128_464() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC79F7FDD0739AF86776A7687DC217A8501BFD24E4B3"),
    )
}

#[test]
fn test_maskedascon128_465() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476620F586508081A133B9A7C902EE007D0BCD5107CDD"),
    )
}

#[test]
fn test_maskedascon128_466() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA11E151534C0F1FC3D3A1B27E5D4947E795730F35B7"),
    )
}

#[test]
fn test_maskedascon128_467() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F018AB62D6E15CC4540D95C497FCECD4B8140115E"),
    )
}

#[test]
fn test_maskedascon128_468() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E1D8D73419C297EA65424D1FB6ACA71C2BB35CA0"),
    )
}

#[test]
fn test_maskedascon128_469() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA010DC49CBBCA554A68B33CE0D6B1C921AABDE21E5"),
    )
}

#[test]
fn test_maskedascon128_470() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D86F9D651795E6364AE7F28021751D665795F13107E"),
    )
}

#[test]
fn test_maskedascon128_471() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC80CBDFFF90B87778D831B33C268A1E2F345BC53"),
    )
}

#[test]
fn test_maskedascon128_472() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC460181575FAD5FD8B0D4B0E17BFADA58D0B1704DD36"),
    )
}

#[test]
fn test_maskedascon128_473() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A067F4D6E69416186F93F1D756B8D8539"),
    )
}

#[test]
fn test_maskedascon128_474() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE58842CB4AED6C6FCC04C876F9893F783713DEB393ED1F"),
    )
}

#[test]
fn test_maskedascon128_475() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D708C5B11AA6D0E531557DFCAF051C0A8A2EA275034"),
    )
}

#[test]
fn test_maskedascon128_476() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC182DF6B59482FC9750406D367C72DB8F1D559809DD"),
    )
}

#[test]
fn test_maskedascon128_477() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BEC2D8A5950F33F2DED3249A60BD255AC1D2949AC"),
    )
}

#[test]
fn test_maskedascon128_478() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9BAB74D02CB78FA4EFE42C665F0111101D241618A"),
    )
}

#[test]
fn test_maskedascon128_479() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01DA8A0EEF496A61B13A0FEED274E2906110A134FE"),
    )
}

#[test]
fn test_maskedascon128_480() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7A496010F11EF2E78EADEE87E6E1FFF5D1B3A24194"),
    )
}

#[test]
fn test_maskedascon128_481() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E67F95B3A91AD955AC4BA7975EDA28EFEDA25CF20"),
    )
}

#[test]
fn test_maskedascon128_482() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C8F134D3E7E9E5DBA53D85D36E48299CF4B975080"),
    )
}

#[test]
fn test_maskedascon128_483() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332F245C70A0571E987538C2C57A6ED8C6BC11B9F76"),
    )
}

#[test]
fn test_maskedascon128_484() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A5C24E497CDE5452FB18BC2A3CB76418D497776C1"),
    )
}

#[test]
fn test_maskedascon128_485() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45978E6F89423901E6F210A135189991CF9F1F3862E5"),
    )
}

#[test]
fn test_maskedascon128_486() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8733301D70F21C889F8B994533F0BDDDF7850406F849103"),
    )
}

#[test]
fn test_maskedascon128_487() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE30914903319CC301D76BFE7A112A34827BC060C4CA"),
    )
}

#[test]
fn test_maskedascon128_488() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD6C1F6BB25A433AF4D4E761460D414568EF2314F0"),
    )
}

#[test]
fn test_maskedascon128_489() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E6314484B8CE06436CC937A7B3CC371D36FEC15BBE5"),
    )
}

#[test]
fn test_maskedascon128_490() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC470C8F261968829D07F56E3F0FBBE5A584393F1C42"),
    )
}

#[test]
fn test_maskedascon128_491() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20D3D705A15FF56CD6F98C3239399793633BFA4F741"),
    )
}

#[test]
fn test_maskedascon128_492() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731641C6EC79EB6876B775211FB5050D2A3C3A7123779"),
    )
}

#[test]
fn test_maskedascon128_493() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99173380199972D19BE4BCFEF42F569A425BD359A32FA6DD6A84"),
    )
}

#[test]
fn test_maskedascon128_494() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BDD82E5155335B6656748D1037784327DF981FC3D"),
    )
}

#[test]
fn test_maskedascon128_495() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1A5D373B05E263B3F65163754B40BE6701016F2EF"),
    )
}

#[test]
fn test_maskedascon128_496() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B29884AD6917516D420A5BC2E5357D010818F0B5F7859"),
    )
}

#[test]
fn test_maskedascon128_497() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC79F7FDD07369A9779D0C974CA41061D4E1250B93D8F0"),
    )
}

#[test]
fn test_maskedascon128_498() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476620F58650864D33F2CFD1B323CADF3356028727A65E6"),
    )
}

#[test]
fn test_maskedascon128_499() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA11E151534C5C86B17754667730F952C0762C2D036649"),
    )
}

#[test]
fn test_maskedascon128_500() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F018AB62DF6B3AFE8414395DBC6225F8096DCA2FAEE"),
    )
}

#[test]
fn test_maskedascon128_501() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E1D8D734515E47320236027C25871944F7C8BA8DB8"),
    )
}

#[test]
fn test_maskedascon128_502() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA010DC49CBA58CC8E14F4CEB3CE83592BFF99C053DE4"),
    )
}

#[test]
fn test_maskedascon128_503() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D86F9D651791D6393E370547CFD0F4CAAE5DDD8503A00"),
    )
}

#[test]
fn test_maskedascon128_504() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC80CBDFF67FB25542F1F646BEC9B625408219371A9"),
    )
}

#[test]
fn test_maskedascon128_505() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC460181575FA9D5D7878157A3BD44533EB5CAC8EAA808E"),
    )
}

#[test]
fn test_maskedascon128_506() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A6764B450C90CB3C232F3FDD3123E2AA099"),
    )
}

#[test]
fn test_maskedascon128_507() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE58842CB4AED6C41E84BD13C5FFA165F9836F5EC8567B117"),
    )
}

#[test]
fn test_maskedascon128_508() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D708C5B11AA14C972AAC92CA70A8D2235C957793BAA9D"),
    )
}

#[test]
fn test_maskedascon128_509() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC182DF6B59467D3BD4E9D996ADF38946367CF3B357314"),
    )
}

#[test]
fn test_maskedascon128_510() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BEC2D8A596B3618CF3D4C7D9A716483683B193A994C"),
    )
}

#[test]
fn test_maskedascon128_511() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9BAB74D02931359CD914FEEAFE892D429E62F3DE0C9"),
    )
}

#[test]
fn test_maskedascon128_512() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01DA8A0EEFB0CDBAC21A17F7627A02B8520502D0A308"),
    )
}

#[test]
fn test_maskedascon128_513() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7A496010F129DC0722BC4625170CC8FBBABCE67AC6D0"),
    )
}

#[test]
fn test_maskedascon128_514() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E67F95B3ABFA1FA8B51439743E4C8B41E4E76B40460"),
    )
}

#[test]
fn test_maskedascon128_515() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C8F134D3ED0FE4BA8BBAEEF96EAB9F7389164447229"),
    )
}

#[test]
fn test_maskedascon128_516() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332F245C70AB246178AEBAC560CBBF26E4610C627B2F4"),
    )
}

#[test]
fn test_maskedascon128_517() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A5C24E4970437D52C2F7DE7354FD3E656BCECBC2FE1"),
    )
}

#[test]
fn test_maskedascon128_518() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45978E6F894249B1B07E0E6A162F76B02B8589F51A8951"),
    )
}

#[test]
fn test_maskedascon128_519() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8733301D70F21C844B48DF953B828308ACF89FFD715CB69E6"),
    )
}

#[test]
fn test_maskedascon128_520() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE3091490331A6D08156FEB3CBDD13E272B7ADD92B5586"),
    )
}

#[test]
fn test_maskedascon128_521() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD6C1F6BB2ED71D67E82B00710770DD02265ED5394C4"),
    )
}

#[test]
fn test_maskedascon128_522() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E6314484B8CA9FF5C393F936453BC89A78944CC2DF2B8"),
    )
}

#[test]
fn test_maskedascon128_523() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC470C8F2619926992D0226C36CB7016F74ABC48E705A2"),
    )
}

#[test]
fn test_maskedascon128_524() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20D3D705A15DB49B1E0CBB2B593BB733424543A51FFA0"),
    )
}

#[test]
fn test_maskedascon128_525() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731641C6EC79E1E17D442384DF3DAF764A888E7B4B53C1C"),
    )
}

#[test]
fn test_maskedascon128_526() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99173380199972D19BE467A0D0A6E122B5F9B342B5107D80152062"),
    )
}

#[test]
fn test_maskedascon128_527() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BDD82E5152FFE0336ED84AD5635C039C7969F31AEC8"),
    )
}

#[test]
fn test_maskedascon128_528() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1A5D373B0D532E2F22E811EFA3311A647577ED0C9E1"),
    )
}

#[test]
fn test_maskedascon128_529() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B29884AD69175C3F58E28436DD71556D58DFA56AC890BEB"),
    )
}

#[test]
fn test_maskedascon128_530() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC79F7FDD07369DD23185CC86B06939E868E420B69A72AEA"),
    )
}

#[test]
fn test_maskedascon128_531() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476620F58650864F069895A94020C6CDCFA13D2AD695C8C83"),
    )
}

#[test]
fn test_maskedascon128_532() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA11E151534C5CCC73FC3B9115AB49D7C9FD7B853CCA8F42"),
    )
}

#[test]
fn test_maskedascon128_533() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F018AB62DF66F70DD20FAEA97E4CA259F28B9056D8F5E"),
    )
}

#[test]
fn test_maskedascon128_534() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E1D8D734511CCA08DB19C090B0901B09ACA853AE16E5"),
    )
}

#[test]
fn test_maskedascon128_535() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA010DC49CBA5537F85A1B05E557291A75CB0DD96C8F81B"),
    )
}

#[test]
fn test_maskedascon128_536() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D86F9D651791D72710F0AC3F792B2D287CA34F7C0C314FE"),
    )
}

#[test]
fn test_maskedascon128_537() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE31614DAC97643C45940A8F9E7964613A"),
    )
}

#[test]
fn test_maskedascon128_538() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC460181575FA9D141B303840EA35902483DCC94992D994DC"),
    )
}

#[test]
fn test_maskedascon128_539() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B1BF245191EFD88892DF3336ADAAC9AC48"),
    )
}

#[test]
fn test_maskedascon128_540() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE58842CB4AED6C41045F54219BA5067337FCCBFEF53ECB879E"),
    )
}

#[test]
fn test_maskedascon128_541() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D708C5B11AA1498217B49CEC36F36D119FAA794A140068C"),
    )
}

#[test]
fn test_maskedascon128_542() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC182DF6B59467721112BC64E6CDA1F41CE542134B7609B5"),
    )
}

#[test]
fn test_maskedascon128_543() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BEC2D8A596B44526E4B15B4B3184A2FC1F7D160E4E972"),
    )
}

#[test]
fn test_maskedascon128_544() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9BAB74D02938E2044DB6FB77058DCC8618539D315E816"),
    )
}

#[test]
fn test_maskedascon128_545() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01DA8A0EEFB0454281D1D3B962418D2E1C8A6D14F3E8A2"),
    )
}

#[test]
fn test_maskedascon128_546() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7A496010F129B5A34081410D25FBBC68B9216046750AE6"),
    )
}

#[test]
fn test_maskedascon128_547() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E67F95B3ABF149935A8D7A204C0FDECFCBCB704B3516E"),
    )
}

#[test]
fn test_maskedascon128_548() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C8F134D3ED02E6C2ABDC9CA80035C91D6B0BD0E10F862"),
    )
}

#[test]
fn test_maskedascon128_549() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332F245C70AB28D23B4B4438820064CF8B2D9245DF12BB9"),
    )
}

#[test]
fn test_maskedascon128_550() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A5C24E4970400DAD3E03324CF89C4B1DF5D6E9680F16E"),
    )
}

#[test]
fn test_maskedascon128_551() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45978E6F894249E8BBBCB07A1DB054668BDE362EA5EE5A8A"),
    )
}

#[test]
fn test_maskedascon128_552() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8733301D70F21C844D954FDC015CBD0B352D9148F4BFBE535E4"),
    )
}

#[test]
fn test_maskedascon128_553() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE3091490331A600685D49DBDFD71E1AC9A566BCE7F5ACBB"),
    )
}

#[test]
fn test_maskedascon128_554() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB509A90C2EDB036C3E14C931F9E0C7F66"),
    )
}

#[test]
fn test_maskedascon128_555() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E6314484B8CA9FF7CE715F655DE23DB4DAB49C1F0520E17"),
    )
}

#[test]
fn test_maskedascon128_556() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC470C8F261992325B4DAC6CCDAFD4EAEA095C95C02D8B0E"),
    )
}

#[test]
fn test_maskedascon128_557() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20D3D705A15DB9B2FE107D3141CC7879EF84B050AEFD142"),
    )
}

#[test]
fn test_maskedascon128_558() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731641C6EC79E1E399C809B7EEC00F1C254DE6C76946FBF80"),
    )
}

#[test]
fn test_maskedascon128_559() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99173380199972D19BE467B6E9CC21E21E4B78EC62FC2D782A0CD9D9"),
    )
}

#[test]
fn test_maskedascon128_560() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BDD82E5152F1465798BC5CCBEA264C14DEA8502F25C04"),
    )
}

#[test]
fn test_maskedascon128_561() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1A5D373B0D51656B8B02AE9C620D98ED6E1F8E5589F64"),
    )
}

#[test]
fn test_maskedascon128_562() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B29884AD69175C33839D3160FF350D4184734773C11BF5603"),
    )
}

#[test]
fn test_maskedascon128_563() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC79F7FDD07369DDF328827210DAEEF1B00B69D0EE9FC7883E"),
    )
}

#[test]
fn test_maskedascon128_564() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476620F58650864F0D56EBD66B687065AEE259D8C30EECA5910"),
    )
}

#[test]
fn test_maskedascon128_565() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA11E151534C5CCC0B84A31C4522D2CFDBA1312EA6648511D6"),
    )
}

#[test]
fn test_maskedascon128_566() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F018AB62DF66F583518C83B060F221E3A1EB59E19424AD5"),
    )
}

#[test]
fn test_maskedascon128_567() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E1D8D734511C32FE42B77F55D173493A512F6384C3FA1A"),
    )
}

#[test]
fn test_maskedascon128_568() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA010DC49CBA553510B46BB397A40B26846C5FE78B1201CDA"),
    )
}

#[test]
fn test_maskedascon128_569() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D86F9D651791D7275FCCBF5894B00F2521682581DC6B57EC7"),
    )
}

#[test]
fn test_maskedascon128_570() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE45F405DA3F52A534524CD268ABAB34DE1C"),
    )
}

#[test]
fn test_maskedascon128_571() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC460181575FA9D145BE9C8D3517D972AF3CEA382275CD02046"),
    )
}

#[test]
fn test_maskedascon128_572() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B15D82C2D8F2C53DF140B314F40FAA288856"),
    )
}

#[test]
fn test_maskedascon128_573() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE58842CB4AED6C41041DE5747C43B1C5F6E021F2A63413077D17"),
    )
}

#[test]
fn test_maskedascon128_574() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D708C5B11AA1498058CDE0A253DE70296009D2F77A46B1C4F"),
    )
}

#[test]
fn test_maskedascon128_575() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC182DF6B59467725AD514C5B75DEEDBB562AFF7B73B9101DB"),
    )
}

#[test]
fn test_maskedascon128_576() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BEC2D8A596B44616D6BAAE57AE50DA0D10248F7F29BCF65"),
    )
}

#[test]
fn test_maskedascon128_577() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9BAB74D02938E9D932C0D3D8B376021E32A7DE6B2E24E86"),
    )
}

#[test]
fn test_maskedascon128_578() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01DA8A0EEFB0455035A06E6E29643AA3B2A2B3AF5ACDD163"),
    )
}

#[test]
fn test_maskedascon128_579() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7A496010F129B5C9F24CC11E01C76F3C9F6F6F41D480BFC8"),
    )
}

#[test]
fn test_maskedascon128_580() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E67F95B3ABF14901DCDABB6153FEE4AF0F1E92FC91EE424"),
    )
}

#[test]
fn test_maskedascon128_581() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C8F134D3ED02E4E9262177C4A75FDA1F0E2C62EE6A47009"),
    )
}

#[test]
fn test_maskedascon128_582() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332F245C70AB28D02B951DB9BA69825EBCC65EE42A2724C49"),
    )
}

#[test]
fn test_maskedascon128_583() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A5C24E4970400CA8AB366C8B5E55FA9C7BDDFF8403ED70E"),
    )
}

#[test]
fn test_maskedascon128_584() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45978E6F894249E8ADE8931AC983F1C07C094B45EAC636F722"),
    )
}

#[test]
fn test_maskedascon128_585() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8733301D70F21C844D9E7DABB5B662840CE5628D0EB0C53F2C236"),
    )
}

#[test]
fn test_maskedascon128_586() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE3091490331A6000BD44420A51F7FCD892F62A972DD5037A1"),
    )
}

#[test]
fn test_maskedascon128_587() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB40788B8784CE35231F88131BD6E1CCC21E"),
    )
}

#[test]
fn test_maskedascon128_588() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E6314484B8CA9FF75AB5C2E7EF5F2B44AECCD96589571C0F7"),
    )
}

#[test]
fn test_maskedascon128_589() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC470C8F26199232AD46A54DD60BF832C0390A94967ECA736E"),
    )
}

#[test]
fn test_maskedascon128_590() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20D3D705A15DB9B75055BA12A156D966BEE896D3657E4E821"),
    )
}

#[test]
fn test_maskedascon128_591() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731641C6EC79E1E39D0F367D35E80C73C60E285A06C1BF76BBD"),
    )
}

#[test]
fn test_maskedascon128_592() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99173380199972D19BE467B6C71C592296ABC7DCB443C1AEE204563184"),
    )
}

#[test]
fn test_maskedascon128_593() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BDD82E5152F149B1FDF764AE096AF5EF06F3B649410D23F"),
    )
}

#[test]
fn test_maskedascon128_594() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1A5D373B0D5168D9FD57F7A9D6C684B8A005CB11EE3A0F0"),
    )
}

#[test]
fn test_maskedascon128_595() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B29884AD69175C33896BB6570B77AA9A0D22DBD95359713DDA7"),
    )
}

#[test]
fn test_maskedascon128_596() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC79F7FDD07369DDF3861BD28D621EDE229828F0F30A0B01A01E"),
    )
}

#[test]
fn test_maskedascon128_597() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476620F58650864F0D5744D68C528C150A1F6DA44571EA0002563"),
    )
}

#[test]
fn test_maskedascon128_598() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA11E151534C5CCC0BEF5983F12F3D14F2F6917679EF250694E9"),
    )
}

#[test]
fn test_maskedascon128_599() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F018AB62DF66F584D0FD10A733A02424B71DE04FDF9088F05"),
    )
}

#[test]
fn test_maskedascon128_600() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E1D8D734511C32CACAC740CBEE43DDBC674AACD895754FA6"),
    )
}

#[test]
fn test_maskedascon128_601() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA010DC49CBA5535101D580542E71D72F8899DCCFE547AF2F6B"),
    )
}

#[test]
fn test_maskedascon128_602() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D86F9D651791D72750F0D00173D8B641715894EA02912D93C69"),
    )
}

#[test]
fn test_maskedascon128_603() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE457EE4FC3BF74D0E7EA8B945F2EB2A898DD7"),
    )
}

#[test]
fn test_maskedascon128_604() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC460181575FA9D145BDD000E0AA31AAE5C17108B00428F98D178"),
    )
}

#[test]
fn test_maskedascon128_605() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B15D9F7EF5A91230C532887C534E22535CE111"),
    )
}

#[test]
fn test_maskedascon128_606() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE58842CB4AED6C41041D6DA262476F2ECF4C58ACCD2BEA2F349FF7"),
    )
}

#[test]
fn test_maskedascon128_607() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D708C5B11AA149805747057E09435AB4A22585BF36AFEFAE03E"),
    )
}

#[test]
fn test_maskedascon128_608() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC182DF6B59467725A70445C48DC636194AA25601AA2B89A769C"),
    )
}

#[test]
fn test_maskedascon128_609() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BEC2D8A596B4461B146BAAD3796EB22B9EDB294870D9C147A"),
    )
}

#[test]
fn test_maskedascon128_610() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9BAB74D02938E9DA2143034F7F3AE086162F8C431BBF322EC"),
    )
}

#[test]
fn test_maskedascon128_611() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01DA8A0EEFB04550CAB1F8CC1E194FE87EAFA8C358226E28D3"),
    )
}

#[test]
fn test_maskedascon128_612() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7A496010F129B5C9A3D1D2EF9E5E3AB15916B293C0CBBC83A0"),
    )
}

#[test]
fn test_maskedascon128_613() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E67F95B3ABF1490F3EEF159D7F59D585D542D06471DDA52E8"),
    )
}

#[test]
fn test_maskedascon128_614() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C8F134D3ED02E4EDB8E5B8314209F5CD94D9236D3728B9DF0"),
    )
}

#[test]
fn test_maskedascon128_615() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332F245C70AB28D022B3ED537B3AB4BECC99A39D2804DB5BCE0"),
    )
}

#[test]
fn test_maskedascon128_616() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A5C24E4970400CA7827CB8081D9E59635A25528469C621BFE"),
    )
}

#[test]
fn test_maskedascon128_617() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45978E6F894249E8ADE01A6038EF6B22B8B0009FD112D6C8CDF1"),
    )
}

#[test]
fn test_maskedascon128_618() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8733301D70F21C844D9E7BA29C8984EB4235F587E7816F6725F1B27"),
    )
}

#[test]
fn test_maskedascon128_619() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE3091490331A6000BCBCA27D18A9AC1A1ACAB65A7060963F098"),
    )
}

#[test]
fn test_maskedascon128_620() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB40288CBD7E70A7ECC1F9AF850DB1D3A32772"),
    )
}

#[test]
fn test_maskedascon128_621() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E6314484B8CA9FF75DC7EA63BFB71CFA709C2EC3E6EEB1A6F33"),
    )
}

#[test]
fn test_maskedascon128_622() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC470C8F26199232AD6D9E39E1276E3265D6301F1D0F471919D0"),
    )
}

#[test]
fn test_maskedascon128_623() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20D3D705A15DB9B7545412128B588A23725159101ECA0C5955B"),
    )
}

#[test]
fn test_maskedascon128_624() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731641C6EC79E1E39D0441CDCF90FB69286194B76BD47C5B5CFDC"),
    )
}

#[test]
fn test_maskedascon128_625() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99173380199972D19BE467B6C78B792BD5DD272A9886432528BD43C8EBC7"),
    )
}

#[test]
fn test_maskedascon128_626() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BDD82E5152F149BFE4A32665E847F526E62B961869F128241"),
    )
}

#[test]
fn test_maskedascon128_627() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1A5D373B0D5168DCACB7A9064D604ECBC4756C25C25808705"),
    )
}

#[test]
fn test_maskedascon128_628() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B29884AD69175C3389655260B684A89F383344B1B58448CE3A062"),
    )
}

#[test]
fn test_maskedascon128_629() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC79F7FDD07369DDF386CA1B7EED9F588EEC0585EA94024E77896F"),
    )
}

#[test]
fn test_maskedascon128_630() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476620F58650864F0D5743B6EF9C19C11089FFA2549053C4461F1AA"),
    )
}

#[test]
fn test_maskedascon128_631() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA11E151534C5CCC0BEFA1060BCCA73055372A6F5F92E1418CC916"),
    )
}

#[test]
fn test_maskedascon128_632() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F018AB62DF66F584D6432E36454E58C325DEFC8E98930EF7690"),
    )
}

#[test]
fn test_maskedascon128_633() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E1D8D734511C32CA445DC34B6E8EF29A17B2B242C43ED39A74"),
    )
}

#[test]
fn test_maskedascon128_634() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA010DC49CBA55351011534D8E692193523F78FB90E54F80C86DE"),
    )
}

#[test]
fn test_maskedascon128_635() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D86F9D651791D72750FE3BEA3408F27B64AC1E044661FCA11487E"),
    )
}

#[test]
fn test_maskedascon128_636() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE457E4226A261F475B9A4628D3AA6F4C21C48B1"),
    )
}

#[test]
fn test_maskedascon128_637() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC460181575FA9D145BDD3D40F465E70C7F8B43C87EB811DE0459CF"),
    )
}

#[test]
fn test_maskedascon128_638() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B15D9FF2B2F7F9EDB877586583C277B830995397"),
    )
}

#[test]
fn test_maskedascon128_639() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE58842CB4AED6C41041D6DECA43936776C15D54263D2CCFB482F3821"),
    )
}

#[test]
fn test_maskedascon128_640() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D708C5B11AA149805748886FC68BFF26F56523038A9634BFBE809"),
    )
}

#[test]
fn test_maskedascon128_641() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC182DF6B59467725A70FAD2257EDD0E5343CCE96914CDB8D1150E"),
    )
}

#[test]
fn test_maskedascon128_642() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BEC2D8A596B4461B16DD1DA38BCE767F4BC796221ACE44A173C"),
    )
}

#[test]
fn test_maskedascon128_643() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9BAB74D02938E9DA2D9C1A1C79F8F8D9E55DAC33422D19263DE"),
    )
}

#[test]
fn test_maskedascon128_644() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01DA8A0EEFB04550CA93206B86C53E96F38643F1EAC3B9FE2618"),
    )
}

#[test]
fn test_maskedascon128_645() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7A496010F129B5C9A3866EF53F0EFBE6F6B4ECDCA6BC70270DC0"),
    )
}

#[test]
fn test_maskedascon128_646() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E67F95B3ABF1490F306C6DB3752200CC9235752C3E0A41B38C8"),
    )
}

#[test]
fn test_maskedascon128_647() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C8F134D3ED02E4EDBA07F2E5FC7096CE6589F25C8DC07076213"),
    )
}

#[test]
fn test_maskedascon128_648() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332F245C70AB28D022B47FFDB1F338ABD07F4C62D0A3C7B1DB660"),
    )
}

#[test]
fn test_maskedascon128_649() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A5C24E4970400CA78DEA9E4F2750CFD52D18CB5B8278B488E28"),
    )
}

#[test]
fn test_maskedascon128_650() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45978E6F894249E8ADE0A17BBBE117725F77DBE1258DC408269C89"),
    )
}

#[test]
fn test_maskedascon128_651() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8733301D70F21C844D9E7BA342CB6620322AD859C9AE5740FEE27BF6E"),
    )
}

#[test]
fn test_maskedascon128_652() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE3091490331A6000BCB733B6423E9E947A4E6A486D397B3563C9B"),
    )
}

#[test]
fn test_maskedascon128_653() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB402824FFABC1A7F01D75DF27090E493FBC0ED1"),
    )
}

#[test]
fn test_maskedascon128_654() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E6314484B8CA9FF75DC66CBC57CBE6E0AE3FA307D2EE177A58594"),
    )
}

#[test]
fn test_maskedascon128_655() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC470C8F26199232AD6DEED65258452E40624216D2A2599AE6EE44"),
    )
}

#[test]
fn test_maskedascon128_656() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20D3D705A15DB9B754566DDB4495B0D1DD5CDAEB1FFF95BC684CA"),
    )
}

#[test]
fn test_maskedascon128_657() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731641C6EC79E1E39D0447634DAB831960367C37BFB9C0B91BC4577"),
    )
}

#[test]
fn test_maskedascon128_658() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99173380199972D19BE467B6C78B40887CD1E10DE712672F6BFD5C8E08D7DD"),
    )
}

#[test]
fn test_maskedascon128_659() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BDD82E5152F149BFE1A77E80F6FF3534F4069508924897650A9"),
    )
}

#[test]
fn test_maskedascon128_660() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1A5D373B0D5168DCA4A8CBA107FE6B9D1459632EF3F96B86226"),
    )
}

#[test]
fn test_maskedascon128_661() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B29884AD69175C3389655CA4AF310AB698B3090A7CBDBF3432D3DD4"),
    )
}

#[test]
fn test_maskedascon128_662() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC79F7FDD07369DDF386CACCBBD49F18ED24EC3747A9DC1C7DDE0F25"),
    )
}

#[test]
fn test_maskedascon128_663() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476620F58650864F0D5743BAA07D68F09EB8D090D5724D487F3023A8D"),
    )
}

#[test]
fn test_maskedascon128_664() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA11E151534C5CCC0BEFA1C3F8FB64C8BD6583DDE77ADF171D1D0097"),
    )
}

#[test]
fn test_maskedascon128_665() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F018AB62DF66F584D643BAC1273081FD86931E93CA453F24E0727"),
    )
}

#[test]
fn test_maskedascon128_666() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E1D8D734511C32CA4415E10196CDE1C6FD04100C89E73AF86DFB"),
    )
}

#[test]
fn test_maskedascon128_667() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA010DC49CBA553510115072F5EC462E050792C12464FAFCCC4F5A6"),
    )
}

#[test]
fn test_maskedascon128_668() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D86F9D651791D72750FE31CDD5F0B73385D39934EABC0456241722D"),
    )
}

#[test]
fn test_maskedascon128_669() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE457E4228C855D481D5E309FBDBB784905DB3DFC1"),
    )
}

#[test]
fn test_maskedascon128_670() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC460181575FA9D145BDD3D6BF3B05571F8DBC017433E9E13F1C09260"),
    )
}

#[test]
fn test_maskedascon128_671() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B15D9FF2815344492269D6E93A9696AA4E49461685"),
    )
}

#[test]
fn test_maskedascon128_672() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE58842CB4AED6C41041D6DEC3B5F557C05ED74645E0B5B07FDFA3EC4BB"),
    )
}

#[test]
fn test_maskedascon128_673() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D708C5B11AA14980574886B72E21A203E6D2330F974B682D1A2DC18"),
    )
}

#[test]
fn test_maskedascon128_674() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC182DF6B59467725A70FA80C0D6A63C9FC06CD31B44640EDB524B24"),
    )
}

#[test]
fn test_maskedascon128_675() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BEC2D8A596B4461B16D086026140E5290276C6327775ED0E4C1F7"),
    )
}

#[test]
fn test_maskedascon128_676() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9BAB74D02938E9DA2D902B5D664F6926A24FC00EEE61F16B650DF"),
    )
}

#[test]
fn test_maskedascon128_677() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01DA8A0EEFB04550CA93CE1B20FED884AF0C7067D1656CEE475A83"),
    )
}

#[test]
fn test_maskedascon128_678() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7A496010F129B5C9A3860BC8EEC2D9B2263B74E0D1784F5C6EE64D"),
    )
}

#[test]
fn test_maskedascon128_679() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E67F95B3ABF1490F306CDF4625E80409F05B0719C6E49A80A4FAB"),
    )
}

#[test]
fn test_maskedascon128_680() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C8F134D3ED02E4EDBA079A23CE7EEB9B4664DDB5F5D1247DC0E2F"),
    )
}

#[test]
fn test_maskedascon128_681() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332F245C70AB28D022B47C186B0449E776F0D6980D44638A0C24370"),
    )
}

#[test]
fn test_maskedascon128_682() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A5C24E4970400CA78DE824E1BC98B6A38037D3428F3AB21D477AC"),
    )
}

#[test]
fn test_maskedascon128_683() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45978E6F894249E8ADE0A149BB7AE2DA0FA056D43C4FDA052309F33F"),
    )
}

#[test]
fn test_maskedascon128_684() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8733301D70F21C844D9E7BA340F6EF8A1C9FC550FA812DD261B6C70D2CC"),
    )
}

#[test]
fn test_maskedascon128_685() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE3091490331A6000BCB7389A8A2D469E118D86BB0C837296505F461"),
    )
}

#[test]
fn test_maskedascon128_686() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB402824D306C64EEE45D243539BFE0E1069217FBD"),
    )
}

#[test]
fn test_maskedascon128_687() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E6314484B8CA9FF75DC6679D3960243E50B17366591A5BFDFF410E2"),
    )
}

#[test]
fn test_maskedascon128_688() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC470C8F26199232AD6DEECACA676D77C823C51C3DA448C7A1AAE19F"),
    )
}

#[test]
fn test_maskedascon128_689() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20D3D705A15DB9B754566D1D05FF63035CCE5744735AB34FBA3D0E2"),
    )
}

#[test]
fn test_maskedascon128_690() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731641C6EC79E1E39D0447608C49202054DC4CE5ED08A36460813813C"),
    )
}

#[test]
fn test_maskedascon128_691() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99173380199972D19BE467B6C78B4088E5B0FDC51BACF2E7129731EAB9957611"),
    )
}

#[test]
fn test_maskedascon128_692() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BDD82E5152F149BFE1A13A6C90E104465EB63D28798D22155A0DD"),
    )
}

#[test]
fn test_maskedascon128_693() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1A5D373B0D5168DCA4A96AB55D515C02182868A73513E7D8492BA"),
    )
}

#[test]
fn test_maskedascon128_694() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B29884AD69175C3389655CA817CDDDDDB4EE51C5C403B0AE24B7D8708"),
    )
}

#[test]
fn test_maskedascon128_695() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC79F7FDD07369DDF386CACC1C9590A1A082168187C08FBCAB96C53044"),
    )
}

#[test]
fn test_maskedascon128_696() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476620F58650864F0D5743BAA43B66BFB59B73A1E3029CB52D20D70275C"),
    )
}

#[test]
fn test_maskedascon128_697() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA11E151534C5CCC0BEFA1C3EFBE84959466CD5541BF4ED5DEE0FC8682"),
    )
}

#[test]
fn test_maskedascon128_698() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F018AB62DF66F584D643B5BFE32E562562BC17904336252B669D9B1"),
    )
}

#[test]
fn test_maskedascon128_699() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E1D8D734511C32CA4415FD7C242A7053D1D6B1753342465AB814E6"),
    )
}

#[test]
fn test_maskedascon128_700() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA010DC49CBA5535101150770F273D2A041CB22ED544792A61DBE7EC5"),
    )
}

#[test]
fn test_maskedascon128_701() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D86F9D651791D72750FE31C29D6B0A52D78DA29D7F1B28C974A817735"),
    )
}

#[test]
fn test_maskedascon128_702() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE457E42289A6B7A72AE0440055570D04783E828E80B"),
    )
}

#[test]
fn test_maskedascon128_703() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC460181575FA9D145BDD3D6B1BDD001B6BB4BCC7C8A24C737883D89C02"),
    )
}

#[test]
fn test_maskedascon128_704() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B15D9FF28142BAE19C560DD6B6722CF219DCF4049140"),
    )
}

#[test]
fn test_maskedascon128_705() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE58842CB4AED6C41041D6DEC3B3AC9C6CD100C70393C119B15991785274D"),
    )
}

#[test]
fn test_maskedascon128_706() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D708C5B11AA14980574886B4C8AA55765BFA9267F8EAEBB38D3ED4E56"),
    )
}

#[test]
fn test_maskedascon128_707() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC182DF6B59467725A70FA80E6608C39AB5C2D7D21CA2BA4F5DFE4F4B1"),
    )
}

#[test]
fn test_maskedascon128_708() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BEC2D8A596B4461B16D08AEAB52612991152894DAF9664063E5ADF0"),
    )
}

#[test]
fn test_maskedascon128_709() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9BAB74D02938E9DA2D902930226854353B8547D18CFFC3D650C073F"),
    )
}

#[test]
fn test_maskedascon128_710() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01DA8A0EEFB04550CA93CE23A437797892B8913E9C9003404A91A6A3"),
    )
}

#[test]
fn test_maskedascon128_711() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7A496010F129B5C9A3860BFF5F9C585268C198B76BBA59E49A932807"),
    )
}

#[test]
fn test_maskedascon128_712() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E67F95B3ABF1490F306CD3749F3DAE6B734BB52F01366B5741970CD"),
    )
}

#[test]
fn test_maskedascon128_713() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C8F134D3ED02E4EDBA0794B47127D200B0283147870A1E45AF980DD"),
    )
}

#[test]
fn test_maskedascon128_714() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332F245C70AB28D022B47C1D015EBAAE30EB8D864C57EC8566B5E540E"),
    )
}

#[test]
fn test_maskedascon128_715() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A5C24E4970400CA78DE82414590B4B7524D50CE73DF27604183A58B"),
    )
}

#[test]
fn test_maskedascon128_716() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45978E6F894249E8ADE0A149F4C564D985B1964585AB4D96E930488C11"),
    )
}

#[test]
fn test_maskedascon128_717() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8733301D70F21C844D9E7BA340F7D6CA2A65BB9813954D611FC81C4FD0AF4"),
    )
}

#[test]
fn test_maskedascon128_718() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE3091490331A6000BCB7389BB96D35124D1E1C92E4DC0554BDC958A7C"),
    )
}

#[test]
fn test_maskedascon128_719() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB402824D3E8255ED6FAA2A920DD3D86ED56BCFD18BE"),
    )
}

#[test]
fn test_maskedascon128_720() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E6314484B8CA9FF75DC667993D5E1524E884961EC39FED07D8F21813A"),
    )
}

#[test]
fn test_maskedascon128_721() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC470C8F26199232AD6DEECA2833FC3010E541DA0AEE55EA221712D463"),
    )
}

#[test]
fn test_maskedascon128_722() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20D3D705A15DB9B754566D10C2DA8265BF5DE7EFE9C0E2066CD7EF4FD"),
    )
}

#[test]
fn test_maskedascon128_723() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731641C6EC79E1E39D04476081D8F6373EDD02AA2BC134D9975B7F4B369"),
    )
}

#[test]
fn test_maskedascon128_724() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99173380199972D19BE467B6C78B4088F975F5DDBF4C94C8DC99DA2513E4EB55BE"),
    )
}

#[test]
fn test_maskedascon128_725() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BDD82E5152F149BFE1A1383B70153B0ACFA4CB9A56260DD86B851E6"),
    )
}

#[test]
fn test_maskedascon128_726() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1A5D373B0D5168DCA4A96736CC5AB9E757CFC6DC4DED82FFB309B24"),
    )
}

#[test]
fn test_maskedascon128_727() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B29884AD69175C3389655CA81353B155C981722AB475C9D51C4DD95F4CF"),
    )
}

#[test]
fn test_maskedascon128_728() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC79F7FDD07369DDF386CACC1CB31432DAE2EFECDEA8E2F6BD311CCC893B"),
    )
}

#[test]
fn test_maskedascon128_729() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476620F58650864F0D5743BAA431B3EF344DA740BB7A3EB3CBA7AB42206E5"),
    )
}

#[test]
fn test_maskedascon128_730() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA11E151534C5CCC0BEFA1C3EF712CBDDB5B77900426D20A1D858CE3557D"),
    )
}

#[test]
fn test_maskedascon128_731() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F018AB62DF66F584D643B5BB5156AED825B303060C9FC19D78ED4CC1E"),
    )
}

#[test]
fn test_maskedascon128_732() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E1D8D734511C32CA4415FD43050024682B3FC2884E66111EAC29324D"),
    )
}

#[test]
fn test_maskedascon128_733() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA010DC49CBA55351011507708E726ED9EC64EDE105946BC0C84201CC3F"),
    )
}

#[test]
fn test_maskedascon128_734() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D86F9D651791D72750FE31C2913311FA3450A1AE9B24C5D55C9BF760D83"),
    )
}

#[test]
fn test_maskedascon128_735() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE457E42289AFBFFD5E650F0B24C5BAAB1FB5419C7DF07"),
    )
}

#[test]
fn test_maskedascon128_736() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC460181575FA9D145BDD3D6B1B7393F82F59D7269C6C44684F7DFDE6E849"),
    )
}

#[test]
fn test_maskedascon128_737() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B15D9FF28142F6FB8B5BA61CD77279E23A5C2D0DABFFDA"),
    )
}

#[test]
fn test_maskedascon128_738() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE58842CB4AED6C41041D6DEC3B3A0D60FE208982F059EAEBC4B18EC8724EE8"),
    )
}

#[test]
fn test_maskedascon128_739() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D708C5B11AA14980574886B4C39686C1318CEDE76C0BFC5288BE5AF1333"),
    )
}

#[test]
fn test_maskedascon128_740() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC182DF6B59467725A70FA80E6A3B602B8D8C2A6D78C3967C9E321655652"),
    )
}

#[test]
fn test_maskedascon128_741() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BEC2D8A596B4461B16D08AE5447399AE7B865FA93F15898E9328CE527"),
    )
}

#[test]
fn test_maskedascon128_742() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9BAB74D02938E9DA2D9029331FEBEADDFED3B5E0DE5EAAFF488716D7D"),
    )
}

#[test]
fn test_maskedascon128_743() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01DA8A0EEFB04550CA93CE23A9BFF1A619D0D3404A01F489767FCAB75F"),
    )
}

#[test]
fn test_maskedascon128_744() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7A496010F129B5C9A3860BFF4158A9902C4A26F0E557B63093E9F9C2A1"),
    )
}

#[test]
fn test_maskedascon128_745() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E67F95B3ABF1490F306CD374B40554E927446842A6213BAA0AB8315CB"),
    )
}

#[test]
fn test_maskedascon128_746() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C8F134D3ED02E4EDBA0794BBA3BDBDFC45BC145817689D69B86875591"),
    )
}

#[test]
fn test_maskedascon128_747() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332F245C70AB28D022B47C1D0D373FF563A2B54BD47864CB8B558E86552"),
    )
}

#[test]
fn test_maskedascon128_748() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A5C24E4970400CA78DE82412DBFC8E290B91B2D163154AB3087DA1D4A"),
    )
}

#[test]
fn test_maskedascon128_749() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45978E6F894249E8ADE0A149F472AA4DF2638B7094F83CD4A65379058614"),
    )
}

#[test]
fn test_maskedascon128_750() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8733301D70F21C844D9E7BA340F7DC4B1A5FAAD296303805AE72B74214799EC"),
    )
}

#[test]
fn test_maskedascon128_751() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE3091490331A6000BCB7389BBBFAED24C4E9769418215BA43D829EA310E"),
    )
}

#[test]
fn test_maskedascon128_752() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB402824D3E814A10FEB8FBEA514A59194A28BDF42F59C"),
    )
}

#[test]
fn test_maskedascon128_753() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E6314484B8CA9FF75DC667993E0DBEDFD8EC9AF19D47C833C832FD8A613"),
    )
}

#[test]
fn test_maskedascon128_754() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC470C8F26199232AD6DEECA28E30F0BDE53D809F15759F77167DE7D91A8"),
    )
}

#[test]
fn test_maskedascon128_755() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20D3D705A15DB9B754566D10C5B84B488D0F47736CD8B00578E26C92FD1"),
    )
}

#[test]
fn test_maskedascon128_756() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731641C6EC79E1E39D04476081D37D3F053C0B637513DC37186286A20D9F8"),
    )
}

#[test]
fn test_maskedascon128_757() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99173380199972D19BE467B6C78B4088F95EEB23DF0BE8AB59979C0C87CF229F207F"),
    )
}

#[test]
fn test_maskedascon128_758() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BDD82E5152F149BFE1A1383E04A674D308099109354D8EAB6CE4E8078"),
    )
}

#[test]
fn test_maskedascon128_759() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1A5D373B0D5168DCA4A96734C5A7CDD5BC26C14028A5ADB64C11DCBCE"),
    )
}

#[test]
fn test_maskedascon128_760() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B29884AD69175C3389655CA8135C9D5E2571D16C89B50A8A0BF0F59940744"),
    )
}

#[test]
fn test_maskedascon128_761() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC79F7FDD07369DDF386CACC1CB31B8E0A38E9E8B1599D29F64FFF7680ECAB"),
    )
}

#[test]
fn test_maskedascon128_762() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476620F58650864F0D5743BAA431BFDBC5235D406C048728C893FCB6D3A1457"),
    )
}

#[test]
fn test_maskedascon128_763() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA11E151534C5CCC0BEFA1C3EF719C928013A663C9CA4B739CAE3AAFE7D354"),
    )
}

#[test]
fn test_maskedascon128_764() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F018AB62DF66F584D643B5BB5F3E743F4E887AE9531FC2BD40F6AC3FE9E"),
    )
}

#[test]
fn test_maskedascon128_765() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E1D8D734511C32CA4415FD432CA8F7BF8C78B8EF274105EAB513824B2F"),
    )
}

#[test]
fn test_maskedascon128_766() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA010DC49CBA55351011507708E1FB6DBC18F92A2DBF12C70A5630EFAFB5C"),
    )
}

#[test]
fn test_maskedascon128_767() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D86F9D651791D72750FE31C291333EFB8B9FF1BE21F81B68080AB0C78A88E"),
    )
}

#[test]
fn test_maskedascon128_768() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE457E42289AFB43D71FEA57922743F8E7BB4118F3E577B2"),
    )
}

#[test]
fn test_maskedascon128_769() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC460181575FA9D145BDD3D6B1B733270DA2ECC428B40B1FB490BB89CF03A00"),
    )
}

#[test]
fn test_maskedascon128_770() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B15D9FF28142F6B7A9FB9C2C3158B935FB8E35DFC07EDC63"),
    )
}

#[test]
fn test_maskedascon128_771() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD69901F988A337A7239C411A18313622FC"),
    )
}

#[test]
fn test_maskedascon128_772() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D708C5B11AA14980574886B4C39215563862991A2D1DE31B7925E66D5634D"),
    )
}

#[test]
fn test_maskedascon128_773() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC182DF6B59467725A70FA80E6A3EB96C1C042224F713A0C4503120C4DCA47"),
    )
}

#[test]
fn test_maskedascon128_774() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BEC2D8A596B4461B16D08AE54D9BDD2515F1810F0AB738502C3028470C6"),
    )
}

#[test]
fn test_maskedascon128_775() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9BAB74D02938E9DA2D9029331F5FFB8C35D7521C52E2A355615204D8F38"),
    )
}

#[test]
fn test_maskedascon128_776() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01DA8A0EEFB04550CA93CE23A9DAFA45957B0265BE12564DA01F48F930FF"),
    )
}

#[test]
fn test_maskedascon128_777() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7A496010F129B5C9A3860BFF41706D224E2E7E214ED53B82C0D532C5D583"),
    )
}

#[test]
fn test_maskedascon128_778() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E67F95B3ABF1490F306CD374BC3E60905EA8478A9C47C465AB9793E8F8B"),
    )
}

#[test]
fn test_maskedascon128_779() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C8F134D3ED02E4EDBA0794BBA65E5B41773DA2EFEBB59D84C4FDBCBC04D"),
    )
}

#[test]
fn test_maskedascon128_780() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332F245C70AB28D022B47C1D0D3133C6987DFFA4E31F7712028EF609D53CE"),
    )
}

#[test]
fn test_maskedascon128_781() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A5C24E4970400CA78DE82412D5BF73B38EF40AEA40FA746F1DE150F0CDF"),
    )
}

#[test]
fn test_maskedascon128_782() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45978E6F894249E8ADE0A149F472B4B0E55F376ACD73DEDAF343575C295C2E"),
    )
}

#[test]
fn test_maskedascon128_783() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8733301D70F21C844D9E7BA340F7DC444590FA42F326CAAE22415AC1FA7896F3E"),
    )
}

#[test]
fn test_maskedascon128_784() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE3091490331A6000BCB7389BBBFCC063C4E5B94AC54DB064472C569A27A05"),
    )
}

#[test]
fn test_maskedascon128_785() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB402824D3E8143C8C252A1F5569A8C2C2AD3AF923FAC6E8"),
    )
}

#[test]
fn test_maskedascon128_786() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E6314484B8CA9FF75DC667993E0EE2FA4448EF1C870BEB075A81B10929BDD"),
    )
}

#[test]
fn test_maskedascon128_787() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC470C8F26199232AD6DEECA28E3408D66CA6E6E887902917EB1CBFC3CFB1D"),
    )
}

#[test]
fn test_maskedascon128_788() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20D3D705A15DB9B754566D10C5B9E8E2239199BA72E35107146A678B0FDFB"),
    )
}

#[test]
fn test_maskedascon128_789() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731641C6EC79E1E39D04476081D37C8CDEE7F6969F5CC3AF30E11F75EA8A684"),
    )
}

#[test]
fn test_maskedascon128_790() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99173380199972D19BE467B6C78B4088F95E42EBD669BC049E3EFCB628ACBFC081659A"),
    )
}

#[test]
fn test_maskedascon128_791() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BDD82E5152F149BFE1A1383E0F42AE0AC49E742D7CB3541A2C50F0BB6FD"),
    )
}

#[test]
fn test_maskedascon128_792() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1A5D373B0D5168DCA4A96734CF0C36330CECE3977B3C3F8E4A94D14BE7D"),
    )
}

#[test]
fn test_maskedascon128_793() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B29884AD69175C3389655CA8135C9E6576F4D9312543671819CBE00BFF09ED5"),
    )
}

#[test]
fn test_maskedascon128_794() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC79F7FDD07369DDF386CACC1CB31BF516AE29B9D376774B5840D2B4407B05BB"),
    )
}

#[test]
fn test_maskedascon128_795() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476620F58650864F0D5743BAA431BFDB01AC7922B93BBC654E3B8955170D0D485"),
    )
}

#[test]
fn test_maskedascon128_796() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA11E151534C5CCC0BEFA1C3EF719C0614F30B22F75E39741E687153BDD4465E"),
    )
}

#[test]
fn test_maskedascon128_797() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F018AB62DF66F584D643B5BB5F3891085EFC807CB291E81C9E265282A6602"),
    )
}

#[test]
fn test_maskedascon128_798() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E1D8D734511C32CA4415FD432CB4698CA4C42E966A40CA6A2995447D9270"),
    )
}

#[test]
fn test_maskedascon128_799() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA010DC49CBA55351011507708E1F02666BCF332621CF585BA76F3BA9C6F245"),
    )
}

#[test]
fn test_maskedascon128_800() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D86F9D651791D72750FE31C291333AC961C5850A8C955BCAC60634527C74817"),
    )
}

#[test]
fn test_maskedascon128_801() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE457E42289AFB4317B8617AB9181B53C30F1FB30082043DBB"),
    )
}

#[test]
fn test_maskedascon128_802() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC460181575FA9D145BDD3D6B1B7332EDCA2EF20CB62511A019C43ABA94D6EF66"),
    )
}

#[test]
fn test_maskedascon128_803() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B15D9FF28142F6B7F2D8CA6B2F561EB67F2A67F12EFC12408B"),
    )
}

#[test]
fn test_maskedascon128_804() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD68F2D79CD508D5EAF3C751AEA24968A3EEE"),
    )
}

#[test]
fn test_maskedascon128_805() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D708C5B11AA14980574886B4C3921B81FE8227372581F160F43E97087418D32"),
    )
}

#[test]
fn test_maskedascon128_806() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC182DF6B59467725A70FA80E6A3EBEDB9D8421D31F415299D31F2CBBBF62401"),
    )
}

#[test]
fn test_maskedascon128_807() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BEC2D8A596B4461B16D08AE54D9FB717755217ABB2640AAEE6764551EB894"),
    )
}

#[test]
fn test_maskedascon128_808() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9BAB74D02938E9DA2D9029331F558DE438BD8686BC4145366CAC82EF62852"),
    )
}

#[test]
fn test_maskedascon128_809() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01DA8A0EEFB04550CA93CE23A9DAAF638A03E693A24AC972C49B4AC5A87C7F"),
    )
}

#[test]
fn test_maskedascon128_810() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7A496010F129B5C9A3860BFF417050697722D253A6457C432B90F671947376"),
    )
}

#[test]
fn test_maskedascon128_811() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E67F95B3ABF1490F306CD374BC3B644F4F46EF8B091ED9740988735AAF327"),
    )
}

#[test]
fn test_maskedascon128_812() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C8F134D3ED02E4EDBA0794BBA6573A97BE1D949587F4C1EA6E30A06D8EB7F"),
    )
}

#[test]
fn test_maskedascon128_813() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332F245C70AB28D022B47C1D0D3135DFFD60971F5E0AD9B05CA76644A7B385F"),
    )
}

#[test]
fn test_maskedascon128_814() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A5C24E4970400CA78DE82412D5B17AB8ABC68D89757D4BDE21D984E122361"),
    )
}

#[test]
fn test_maskedascon128_815() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45978E6F894249E8ADE0A149F472B44C34B84BED02CB4ABF95CFC81931BCD5B8"),
    )
}

#[test]
fn test_maskedascon128_816() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8733301D70F21C844D9E7BA340F7DC4441517D59F796563344B8A7E2E395BB9F9E2"),
    )
}

#[test]
fn test_maskedascon128_817() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE3091490331A6000BCB7389BBBFCC921A065889B87D3DBF7DC7D5AAF7C66DC7"),
    )
}

#[test]
fn test_maskedascon128_818() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB402824D3E8143C08E6E876865F8B73048D126C6C40C7E8AE"),
    )
}

#[test]
fn test_maskedascon128_819() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E6314484B8CA9FF75DC667993E0EE22D5251D764B978F6133C6FCF8D2A3C541"),
    )
}

#[test]
fn test_maskedascon128_820() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC470C8F26199232AD6DEECA28E340E2F3E0A717A1C4A24ACF11E230F41AFE67"),
    )
}

#[test]
fn test_maskedascon128_821() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20D3D705A15DB9B754566D10C5B9ECB1EC11004F2975CBE73B1E67503165FD0"),
    )
}

#[test]
fn test_maskedascon128_822() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731641C6EC79E1E39D04476081D37C89D6D3991E2E9C19178A0C7B692785B78C1"),
    )
}

#[test]
fn test_maskedascon128_823() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99173380199972D19BE467B6C78B4088F95E422B31264AC40E91DAB8560494655AA5F579"),
    )
}

#[test]
fn test_maskedascon128_824() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BDD82E5152F149BFE1A1383E0F46B34077FF11AA6CF80967695BC45EC5D25"),
    )
}

#[test]
fn test_maskedascon128_825() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1A5D373B0D5168DCA4A96734CF0DD32BC3AAEE2C8C7649298EE9C5ED5F8F8"),
    )
}

#[test]
fn test_maskedascon128_826() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!(""),
        &hex!("BC820DBDF7A4631C5B29884AD69175C3389655CA8135C9E6E8BD5E04471B664ECFCF5C45FC08A92C91"),
    )
}

#[test]
fn test_maskedascon128_827() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("00"),
        &hex!("BD4640C4DA2FFA56DC79F7FDD07369DDF386CACC1CB31BF59262507D8B92B3BF91604E3C00CB015673"),
    )
}

#[test]
fn test_maskedascon128_828() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("0001"),
        &hex!("6E9F820D5468A0D476620F58650864F0D5743BAA431BFDB037675F110E016A1CA24A270D2EBDA44FA2"),
    )
}

#[test]
fn test_maskedascon128_829() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102"),
        &hex!("F19D28E0F222B3BFCA11E151534C5CCC0BEFA1C3EF719C06CC2A322BB24BCCAEAC78736EE17DCC688B"),
    )
}

#[test]
fn test_maskedascon128_830() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("00010203"),
        &hex!("7763F8BA6CE91ED1684F018AB62DF66F584D643B5BB5F3896A033953DA18F305025FB98D16AFCDD6D3"),
    )
}

#[test]
fn test_maskedascon128_831() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("0001020304"),
        &hex!("0E6A8B0CA517F53D3D72E1D8D734511C32CA4415FD432CB48A5DB5937A93BBB8480B7D61F8AF5B67EB"),
    )
}

#[test]
fn test_maskedascon128_832() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405"),
        &hex!("5B513546B1A1DC8AAAA010DC49CBA55351011507708E1F0219D75D83AB6B1B656A9405BD6696E965BF"),
    )
}

#[test]
fn test_maskedascon128_833() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("00010203040506"),
        &hex!("2E5BBADE9599AC9F2D86F9D651791D72750FE31C291333ACCEF1C4534A94D8C0E73F8B27130E5C5FD1"),
    )
}

#[test]
fn test_maskedascon128_834() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("0001020304050607"),
        &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE457E42289AFB4317B24683408CB50B209487262CAB9442EAD4"),
    )
}

#[test]
fn test_maskedascon128_835() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708"),
        &hex!("3225026599BCD4FCC460181575FA9D145BDD3D6B1B7332ED3D46B3B4F9B224896306560F12D07600A7"),
    )
}

#[test]
fn test_maskedascon128_836() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("00010203040506070809"),
        &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B15D9FF28142F6B7F25D9CC0022A69BA5137C3898BAD30B4B24C"),
    )
}

#[test]
fn test_maskedascon128_837() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A"),
        &hex!("76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD68FBF1F0B8EE355CE2BB2B2C68C1E3D09DAEA"),
    )
}

#[test]
fn test_maskedascon128_838() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B"),
        &hex!("59B3A5338CD171F93D708C5B11AA14980574886B4C3921B84D5E90EED07FEC186464FAADE49DE07B12"),
    )
}

#[test]
fn test_maskedascon128_839() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("8462C376C06AAE28BC182DF6B59467725A70FA80E6A3EBED6A7498CCBF928BE9A78367CE98901299B5"),
    )
}

#[test]
fn test_maskedascon128_840() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("2E325340DF7FD0BFD25BEC2D8A596B4461B16D08AE54D9FB60E2CF9898787BEF4AB16EA87010C8B9FB"),
    )
}

#[test]
fn test_maskedascon128_841() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("2E83CC36F088232A8EE9BAB74D02938E9DA2D9029331F558ED7AD0F96F6AE66E850241501309003E89"),
    )
}

#[test]
fn test_maskedascon128_842() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("1EE34125FDBA17443D01DA8A0EEFB04550CA93CE23A9DAAF0D38BE83CA09896B101B5BBE6541ECE5AA"),
    )
}

#[test]
fn test_maskedascon128_843() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("8684539A9FCFF9F68A7A496010F129B5C9A3860BFF417050D08353F8763A436FE69410A0F9CB51B727"),
    )
}

#[test]
fn test_maskedascon128_844() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("77AA511159627C4B855E67F95B3ABF1490F306CD374BC3B6C7BDC6E79814CD5757FA4935F2B525D431"),
    )
}

#[test]
fn test_maskedascon128_845() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("D323863E597297EAB51C8F134D3ED02E4EDBA0794BBA65739B30C5A5AF711FE0A6884125F4D1E26582"),
    )
}

#[test]
fn test_maskedascon128_846() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("A31AC9A1D4D18222F332F245C70AB28D022B47C1D0D3135D347CA598EDFEDAC91C0E10B4AEC1C7A9BA"),
    )
}

#[test]
fn test_maskedascon128_847() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("74EA9BA2635DCBAA400A5C24E4970400CA78DE82412D5B177CF9DB726A5A274B298C93EFC832461A6F"),
    )
}

#[test]
fn test_maskedascon128_848() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("ADBB720C2D415EEC45978E6F894249E8ADE0A149F472B44C1D5D1448D8BD1EF77BFA1D8161A160334F"),
    )
}

#[test]
fn test_maskedascon128_849() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("3B29669395DAB8733301D70F21C844D9E7BA340F7DC44415E9F4472974B12180264F7A1DFE2020A5C5"),
    )
}

#[test]
fn test_maskedascon128_850() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("74A6A39D0A512958EE3091490331A6000BCB7389BBBFCC92C7D0EDF74EB26262B4D30919E5FDA176E2"),
    )
}

#[test]
fn test_maskedascon128_851() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB402824D3E8143C0875557AC563C51746A50BA43AF062811CBC"),
    )
}

#[test]
fn test_maskedascon128_852() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("2D134D2DE994DEC27E6314484B8CA9FF75DC667993E0EE22C40E7149806AF158E922D1DA62FB79B01F"),
    )
}

#[test]
fn test_maskedascon128_853() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("31686725B47CA995FC470C8F26199232AD6DEECA28E340E2E690AB6ED71FD9E638E55BB95FDDF50717"),
    )
}

#[test]
fn test_maskedascon128_854() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("C780135837218C32D20D3D705A15DB9B754566D10C5B9ECB226938C3B8757888721678A259DB85CA99"),
    )
}

#[test]
fn test_maskedascon128_855() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("3BD2F45CE90E0F3731641C6EC79E1E39D04476081D37C89DA90BCA6DA42D8B195A834F992ADB1FEB82"),
    )
}

#[test]
fn test_maskedascon128_856() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("270D846F99173380199972D19BE467B6C78B4088F95E422B2FB5E88617CBEC383298634488B3CA2472"),
    )
}

#[test]
fn test_maskedascon128_857() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("D670F5A44971BE13F91BDD82E5152F149BFE1A1383E0F46BAD6133DDB047A077CEEC4A2A6B52AD47AA"),
    )
}

#[test]
fn test_maskedascon128_858() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("B96C78651B6246B0C3B1A5D373B0D5168DCA4A96734CF0DDF5D7FB48F9ED73CC1BF403E5406C67F2E2"),
    )
}

#[test]
fn test_maskedascon128_859() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!(""),
        &hex!(
            "BC820DBDF7A4631C5B29884AD69175C3389655CA8135C9E6E8FEE8AD23AADE658E616DB4E6466A321CA8"
        ),
    )
}

#[test]
fn test_maskedascon128_860() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("00"),
        &hex!(
            "BD4640C4DA2FFA56DC79F7FDD07369DDF386CACC1CB31BF592F669BA03B1FA8E1FD495E5021DE4069A82"
        ),
    )
}

#[test]
fn test_maskedascon128_861() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("0001"),
        &hex!(
            "6E9F820D5468A0D476620F58650864F0D5743BAA431BFDB037F8DCB92E442AC53BD8414C22CEDED215AF"
        ),
    )
}

#[test]
fn test_maskedascon128_862() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102"),
        &hex!(
            "F19D28E0F222B3BFCA11E151534C5CCC0BEFA1C3EF719C06CC91D2241549428CE5A64FD2B4B4845D2CCD"
        ),
    )
}

#[test]
fn test_maskedascon128_863() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("00010203"),
        &hex!(
            "7763F8BA6CE91ED1684F018AB62DF66F584D643B5BB5F3896A4C4EF959D32AA63290AB4E3F20AC98BCA4"
        ),
    )
}

#[test]
fn test_maskedascon128_864() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("0001020304"),
        &hex!(
            "0E6A8B0CA517F53D3D72E1D8D734511C32CA4415FD432CB48AD69AD14E136ED7572CE147431760782A16"
        ),
    )
}

#[test]
fn test_maskedascon128_865() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405"),
        &hex!(
            "5B513546B1A1DC8AAAA010DC49CBA55351011507708E1F021937C310A9C80EED4B054503BF65069FE6C6"
        ),
    )
}

#[test]
fn test_maskedascon128_866() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("00010203040506"),
        &hex!(
            "2E5BBADE9599AC9F2D86F9D651791D72750FE31C291333ACCE975F96EB2EAAB5FE4250EA36051D40A599"
        ),
    )
}

#[test]
fn test_maskedascon128_867() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("0001020304050607"),
        &hex!(
            "69FFEE6F5505A4897E2EC80CBDFF67CE457E42289AFB4317B2F433199AD0F084978D3DA390107152E492"
        ),
    )
}

#[test]
fn test_maskedascon128_868() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708"),
        &hex!(
            "3225026599BCD4FCC460181575FA9D145BDD3D6B1B7332ED3D2687788373498251596945EC8683F8BE10"
        ),
    )
}

#[test]
fn test_maskedascon128_869() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("00010203040506070809"),
        &hex!(
            "3DDCE4DEABF18BBB4BF4EDACCE9A67B15D9FF28142F6B7F25DF984C071062CEB135F2858AB7E5130C6DE"
        ),
    )
}

#[test]
fn test_maskedascon128_870() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A"),
        &hex!(
            "76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD68FBFF11012B9ED70AA53EB1798E18514284986"
        ),
    )
}

#[test]
fn test_maskedascon128_871() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B"),
        &hex!(
            "59B3A5338CD171F93D708C5B11AA14980574886B4C3921B84DB594FBB5F97BFB47DD7A3DE88008C21BBF"
        ),
    )
}

#[test]
fn test_maskedascon128_872() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C"),
        &hex!(
            "8462C376C06AAE28BC182DF6B59467725A70FA80E6A3EBED6ADE864A10A82D5AD78CC6BB3162A2161AFB"
        ),
    )
}

#[test]
fn test_maskedascon128_873() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!(
            "2E325340DF7FD0BFD25BEC2D8A596B4461B16D08AE54D9FB609F06D6953FA8F77AA570065490E62106C1"
        ),
    )
}

#[test]
fn test_maskedascon128_874() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!(
            "2E83CC36F088232A8EE9BAB74D02938E9DA2D9029331F558ED3800B9FB3361AEBC242F5F4E64DADA4FCF"
        ),
    )
}

#[test]
fn test_maskedascon128_875() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(
            "1EE34125FDBA17443D01DA8A0EEFB04550CA93CE23A9DAAF0D7B099A344EE66E6CB18A506CC8AA3E66E0"
        ),
    )
}

#[test]
fn test_maskedascon128_876() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!(
            "8684539A9FCFF9F68A7A496010F129B5C9A3860BFF417050D028C8CF6CD5A1B74BAB88DC1768F5022320"
        ),
    )
}

#[test]
fn test_maskedascon128_877() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!(
            "77AA511159627C4B855E67F95B3ABF1490F306CD374BC3B6C7BA9E63FBEB1D0A1BAC918B6A397C49AF69"
        ),
    )
}

#[test]
fn test_maskedascon128_878() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!(
            "D323863E597297EAB51C8F134D3ED02E4EDBA0794BBA65739BDFB8E5D45B2FFB308B220D10D35CA93E07"
        ),
    )
}

#[test]
fn test_maskedascon128_879() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!(
            "A31AC9A1D4D18222F332F245C70AB28D022B47C1D0D3135D34F5CCF59C551B21CC2CB55228C5F90F4B34"
        ),
    )
}

#[test]
fn test_maskedascon128_880() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!(
            "74EA9BA2635DCBAA400A5C24E4970400CA78DE82412D5B177C5D2117C244929CCAFAB8E73CDDC2BCF852"
        ),
    )
}

#[test]
fn test_maskedascon128_881() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!(
            "ADBB720C2D415EEC45978E6F894249E8ADE0A149F472B44C1D0E4E6054E138A6DB0B0B5AF436BC498201"
        ),
    )
}

#[test]
fn test_maskedascon128_882() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!(
            "3B29669395DAB8733301D70F21C844D9E7BA340F7DC44415E91A3AF916DF7D99A4ACDDFC9081306A6F2F"
        ),
    )
}

#[test]
fn test_maskedascon128_883() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!(
            "74A6A39D0A512958EE3091490331A6000BCB7389BBBFCC92C75A6C01D0A0248519971154C9A9CE43ABD7"
        ),
    )
}

#[test]
fn test_maskedascon128_884() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!(
            "2970E5D3DCDED18D81CD6C1F6BB2EDBB402824D3E8143C0875EB068A6B6CDEA2B247B21586E9D810D597"
        ),
    )
}

#[test]
fn test_maskedascon128_885() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!(
            "2D134D2DE994DEC27E6314484B8CA9FF75DC667993E0EE22C4CC5261BF011A34D574B072DE100BF56C75"
        ),
    )
}

#[test]
fn test_maskedascon128_886() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!(
            "31686725B47CA995FC470C8F26199232AD6DEECA28E340E2E6D86025BFE0C752294793E34319BB2CD6ED"
        ),
    )
}

#[test]
fn test_maskedascon128_887() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!(
            "C780135837218C32D20D3D705A15DB9B754566D10C5B9ECB22AA568DBE90627BD947A5E14170B34FF9D3"
        ),
    )
}

#[test]
fn test_maskedascon128_888() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!(
            "3BD2F45CE90E0F3731641C6EC79E1E39D04476081D37C89DA94387BDC344E906BCC2DF2F19D3DCCAB86D"
        ),
    )
}

#[test]
fn test_maskedascon128_889() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!(
            "270D846F99173380199972D19BE467B6C78B4088F95E422B2F13F4AB0D2CED6A3113AF44BF6491C77DDA"
        ),
    )
}

#[test]
fn test_maskedascon128_890() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!(
            "D670F5A44971BE13F91BDD82E5152F149BFE1A1383E0F46BADA40177380D75E8A00656CD22AE908B6BAB"
        ),
    )
}

#[test]
fn test_maskedascon128_891() {
    run_tv::<MaskedAscon128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!(
            "B96C78651B6246B0C3B1A5D373B0D5168DCA4A96734CF0DDF5F98371332D7EB9742CA82634182AB3F23C"
        ),
    )
}

#[test]
fn test_maskedascon128_892() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!(""),
      &hex!("BC820DBDF7A4631C5B29884AD69175C3389655CA8135C9E6E8FE7440B86B2D278B33DD4CEB82762E573984"),
    )
}

#[test]
fn test_maskedascon128_893() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("00"),
      &hex!("BD4640C4DA2FFA56DC79F7FDD07369DDF386CACC1CB31BF592F6AEE8F62B3012B6CD142858D0F8C4CC9B10"),
    )
}

#[test]
fn test_maskedascon128_894() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("0001"),
      &hex!("6E9F820D5468A0D476620F58650864F0D5743BAA431BFDB037F8A33D0AA523A7BD6F758ADEA066279E2DED"),
    )
}

#[test]
fn test_maskedascon128_895() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102"),
      &hex!("F19D28E0F222B3BFCA11E151534C5CCC0BEFA1C3EF719C06CC916089B7F3719FD84D1381BF4AFB42FD90E1"),
    )
}

#[test]
fn test_maskedascon128_896() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("00010203"),
      &hex!("7763F8BA6CE91ED1684F018AB62DF66F584D643B5BB5F3896A4C74D6B308229995BA5647C60F29121B1505"),
    )
}

#[test]
fn test_maskedascon128_897() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("0001020304"),
      &hex!("0E6A8B0CA517F53D3D72E1D8D734511C32CA4415FD432CB48AD6AD44F720C373F9F85F6063F31917A3399F"),
    )
}

#[test]
fn test_maskedascon128_898() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405"),
      &hex!("5B513546B1A1DC8AAAA010DC49CBA55351011507708E1F021937498C770D8DF6C712B3BAADF9E54D877209"),
    )
}

#[test]
fn test_maskedascon128_899() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("00010203040506"),
      &hex!("2E5BBADE9599AC9F2D86F9D651791D72750FE31C291333ACCE97C475AA4360FB26097F2A47A7D5E16341DF"),
    )
}

#[test]
fn test_maskedascon128_900() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("0001020304050607"),
      &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE457E42289AFB4317B2F4B6C5C822FCCD5D264A65739E27742E8BE4"),
    )
}

#[test]
fn test_maskedascon128_901() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708"),
      &hex!("3225026599BCD4FCC460181575FA9D145BDD3D6B1B7332ED3D26464E0A4090215EEDB8B007A09AA8FACCE0"),
    )
}

#[test]
fn test_maskedascon128_902() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("00010203040506070809"),
      &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B15D9FF28142F6B7F25DF90EE19AE8BC9439E8ADB4C21FA7F05B0686"),
    )
}

#[test]
fn test_maskedascon128_903() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A"),
      &hex!("76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD68FBFF1BEFEDF4C5E7B528AB45C4BB0F7875F2F60"),
    )
}

#[test]
fn test_maskedascon128_904() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B"),
      &hex!("59B3A5338CD171F93D708C5B11AA14980574886B4C3921B84DB5A48A30AC9D3806CAE0EEE8C725487DC9F7"),
    )
}

#[test]
fn test_maskedascon128_905() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C"),
      &hex!("8462C376C06AAE28BC182DF6B59467725A70FA80E6A3EBED6ADEF4293A805926923E3D1AC627892166E00E"),
    )
}

#[test]
fn test_maskedascon128_906() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D"),
      &hex!("2E325340DF7FD0BFD25BEC2D8A596B4461B16D08AE54D9FB609FFCB32A09701FE0DEFFFF09A44F4F9A108E"),
    )
}

#[test]
fn test_maskedascon128_907() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E"),
      &hex!("2E83CC36F088232A8EE9BAB74D02938E9DA2D9029331F558ED383591D4751020B17C59BAF48F04F4D9D813"),
    )
}

#[test]
fn test_maskedascon128_908() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("1EE34125FDBA17443D01DA8A0EEFB04550CA93CE23A9DAAF0D7BDD81EB192B98BCAA6793D1F071BF135970"),
    )
}

#[test]
fn test_maskedascon128_909() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F10"),
      &hex!("8684539A9FCFF9F68A7A496010F129B5C9A3860BFF417050D0281DCB0E87B1A6025C96455A3FDBF9D506AA"),
    )
}

#[test]
fn test_maskedascon128_910() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F1011"),
      &hex!("77AA511159627C4B855E67F95B3ABF1490F306CD374BC3B6C7BACE4CF349C93429B357B16EBFF1BAE75934"),
    )
}

#[test]
fn test_maskedascon128_911() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F101112"),
      &hex!("D323863E597297EAB51C8F134D3ED02E4EDBA0794BBA65739BDF24023984ECA2D20C3993777675E0575CF8"),
    )
}

#[test]
fn test_maskedascon128_912() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213"),
      &hex!("A31AC9A1D4D18222F332F245C70AB28D022B47C1D0D3135D34F551B7CA91DFDDB246D69675DE203E128792"),
    )
}

#[test]
fn test_maskedascon128_913() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
      &hex!("74EA9BA2635DCBAA400A5C24E4970400CA78DE82412D5B177C5DA6B0BD55571275E8E5F83255B21D535BCE"),
    )
}

#[test]
fn test_maskedascon128_914() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
      &hex!("ADBB720C2D415EEC45978E6F894249E8ADE0A149F472B44C1D0E1EB0D94CFF4F35A6C3E23F412DC0C9D3CF"),
    )
}

#[test]
fn test_maskedascon128_915() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
      &hex!("3B29669395DAB8733301D70F21C844D9E7BA340F7DC44415E91AF7485FBB9A27C4649BC59213191CA966C4"),
    )
}

#[test]
fn test_maskedascon128_916() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
      &hex!("74A6A39D0A512958EE3091490331A6000BCB7389BBBFCC92C75A4DAE26667986A1CED2618D6D0FB1DF83EB"),
    )
}

#[test]
fn test_maskedascon128_917() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
      &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB402824D3E8143C0875EB55B22A256BA2453633FAE2EE5DFF70CB74"),
    )
}

#[test]
fn test_maskedascon128_918() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
      &hex!("2D134D2DE994DEC27E6314484B8CA9FF75DC667993E0EE22C4CC8640B78A3F936932720C10092FAEB4C3F4"),
    )
}

#[test]
fn test_maskedascon128_919() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("31686725B47CA995FC470C8F26199232AD6DEECA28E340E2E6D8AD66672F11EB628C7A7F50DD695EEEAC9F"),
    )
}

#[test]
fn test_maskedascon128_920() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("C780135837218C32D20D3D705A15DB9B754566D10C5B9ECB22AAB4857B2D27FAA7808EA6D195599B10D626"),
    )
}

#[test]
fn test_maskedascon128_921() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("3BD2F45CE90E0F3731641C6EC79E1E39D04476081D37C89DA943ACD1F7F599E499ED000AC7ECBE4F412280"),
    )
}

#[test]
fn test_maskedascon128_922() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("270D846F99173380199972D19BE467B6C78B4088F95E422B2F1382ED0E7103BFB61FA83C90275823211A58"),
    )
}

#[test]
fn test_maskedascon128_923() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("D670F5A44971BE13F91BDD82E5152F149BFE1A1383E0F46BADA4B04BFA9947FDFD583F8974879437543023"),
    )
}

#[test]
fn test_maskedascon128_924() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("B96C78651B6246B0C3B1A5D373B0D5168DCA4A96734CF0DDF5F92FB94EE6BF3C68BD2086F40F01325F5A51"),
    )
}

#[test]
fn test_maskedascon128_925() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!(""),
      &hex!("BC820DBDF7A4631C5B29884AD69175C3389655CA8135C9E6E8FE7467036F18683223DE55B84A1621E444AD9A"),
    )
}

#[test]
fn test_maskedascon128_926() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("00"),
      &hex!("BD4640C4DA2FFA56DC79F7FDD07369DDF386CACC1CB31BF592F6AE1B1867495B1E2E128A542F136A468C886B"),
    )
}

#[test]
fn test_maskedascon128_927() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("0001"),
      &hex!("6E9F820D5468A0D476620F58650864F0D5743BAA431BFDB037F8A32BDA8B4B7EBFA1DEB35E80A2127076F678"),
    )
}

#[test]
fn test_maskedascon128_928() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102"),
      &hex!("F19D28E0F222B3BFCA11E151534C5CCC0BEFA1C3EF719C06CC916012F6C5F0C90BC14A4B27C33A105732AED9"),
    )
}

#[test]
fn test_maskedascon128_929() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("00010203"),
      &hex!("7763F8BA6CE91ED1684F018AB62DF66F584D643B5BB5F3896A4C74401C75E5ED7419C2D4FF17E9D4D363993B"),
    )
}

#[test]
fn test_maskedascon128_930() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("0001020304"),
      &hex!("0E6A8B0CA517F53D3D72E1D8D734511C32CA4415FD432CB48AD6ADEB4E561588178AA5912A33DE8D967409B7"),
    )
}

#[test]
fn test_maskedascon128_931() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405"),
      &hex!("5B513546B1A1DC8AAAA010DC49CBA55351011507708E1F02193749928D705037D7984E2C4814E6DF2CEC14C4"),
    )
}

#[test]
fn test_maskedascon128_932() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("00010203040506"),
      &hex!("2E5BBADE9599AC9F2D86F9D651791D72750FE31C291333ACCE97C4FBBFE94CEDF99B31FB251AEB8964FB6879"),
    )
}

#[test]
fn test_maskedascon128_933() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("0001020304050607"),
      &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE457E42289AFB4317B2F4B6A909496CE11CFC27944B36E13778108EDA"),
    )
}

#[test]
fn test_maskedascon128_934() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708"),
      &hex!("3225026599BCD4FCC460181575FA9D145BDD3D6B1B7332ED3D26467D901BEDBD838FA7FF39FD7DF6B342D073"),
    )
}

#[test]
fn test_maskedascon128_935() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("00010203040506070809"),
      &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B15D9FF28142F6B7F25DF90E24F7671C98791191AD550BD3FB4281A629"),
    )
}

#[test]
fn test_maskedascon128_936() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A"),
      &hex!("76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD68FBFF1BECB229320CAC40251F88CEC53A34C904921"),
    )
}

#[test]
fn test_maskedascon128_937() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B"),
      &hex!("59B3A5338CD171F93D708C5B11AA14980574886B4C3921B84DB5A4A9F6E19AD3DD5DCED6271539543A078B27"),
    )
}

#[test]
fn test_maskedascon128_938() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C"),
      &hex!("8462C376C06AAE28BC182DF6B59467725A70FA80E6A3EBED6ADEF40DA31D93051A7275F5D8EBB626E896CD35"),
    )
}

#[test]
fn test_maskedascon128_939() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D"),
      &hex!("2E325340DF7FD0BFD25BEC2D8A596B4461B16D08AE54D9FB609FFC7134D399E34E27AF40D772B32B90C7D151"),
    )
}

#[test]
fn test_maskedascon128_940() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E"),
      &hex!("2E83CC36F088232A8EE9BAB74D02938E9DA2D9029331F558ED3835574FF6714108CA5FF50C984717F837DB0B"),
    )
}

#[test]
fn test_maskedascon128_941() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("1EE34125FDBA17443D01DA8A0EEFB04550CA93CE23A9DAAF0D7BDD7E38222AA3229B214B6EC771A21616C54C"),
    )
}

#[test]
fn test_maskedascon128_942() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F10"),
      &hex!("8684539A9FCFF9F68A7A496010F129B5C9A3860BFF417050D0281D0B5BAB21A3FCDA1CAEB61D3E6D1B5A3583"),
    )
}

#[test]
fn test_maskedascon128_943() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F1011"),
      &hex!("77AA511159627C4B855E67F95B3ABF1490F306CD374BC3B6C7BACE95B209218686A839BD85F8DDA773492E38"),
    )
}

#[test]
fn test_maskedascon128_944() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F101112"),
      &hex!("D323863E597297EAB51C8F134D3ED02E4EDBA0794BBA65739BDF2403949DDF12C8C453A9CBD39BD1F9D76795"),
    )
}

#[test]
fn test_maskedascon128_945() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213"),
      &hex!("A31AC9A1D4D18222F332F245C70AB28D022B47C1D0D3135D34F551684A04712AED3C67B612645BD214353254"),
    )
}

#[test]
fn test_maskedascon128_946() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
      &hex!("74EA9BA2635DCBAA400A5C24E4970400CA78DE82412D5B177C5DA6BE661610382F1CEA890FB2F9D724835D46"),
    )
}

#[test]
fn test_maskedascon128_947() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
      &hex!("ADBB720C2D415EEC45978E6F894249E8ADE0A149F472B44C1D0E1E5722A397B39481562A4EF61F38AB1FE594"),
    )
}

#[test]
fn test_maskedascon128_948() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
      &hex!("3B29669395DAB8733301D70F21C844D9E7BA340F7DC44415E91AF7522EE244CF54E4752F95D04B109FED8326"),
    )
}

#[test]
fn test_maskedascon128_949() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
      &hex!("74A6A39D0A512958EE3091490331A6000BCB7389BBBFCC92C75A4D79792A9EB82685EDDDDFCA85E7162A1AB7"),
    )
}

#[test]
fn test_maskedascon128_950() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
      &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB402824D3E8143C0875EB55B99422C2EFBD7EFBC68A2AC4E8252B3702"),
    )
}

#[test]
fn test_maskedascon128_951() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
      &hex!("2D134D2DE994DEC27E6314484B8CA9FF75DC667993E0EE22C4CC866744F0588E0D924F0A7AE482B017C36F60"),
    )
}

#[test]
fn test_maskedascon128_952() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("31686725B47CA995FC470C8F26199232AD6DEECA28E340E2E6D8AD60846553157F509F690CE1F342150A7112"),
    )
}

#[test]
fn test_maskedascon128_953() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("C780135837218C32D20D3D705A15DB9B754566D10C5B9ECB22AAB461DAE41D93496802E70FA8F9C580A4273D"),
    )
}

#[test]
fn test_maskedascon128_954() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("3BD2F45CE90E0F3731641C6EC79E1E39D04476081D37C89DA943AC8981968540319FC065C66C033FA2D21F1A"),
    )
}

#[test]
fn test_maskedascon128_955() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("270D846F99173380199972D19BE467B6C78B4088F95E422B2F1382EDEFD6A385ED5F693DD833BE48E86B4FF1"),
    )
}

#[test]
fn test_maskedascon128_956() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("D670F5A44971BE13F91BDD82E5152F149BFE1A1383E0F46BADA4B03B6E95F98CDFD0C49855C8193AD116301F"),
    )
}

#[test]
fn test_maskedascon128_957() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("B96C78651B6246B0C3B1A5D373B0D5168DCA4A96734CF0DDF5F92F8D21D7BD579A5871F28C5792F7E1D40839"),
    )
}

#[test]
fn test_maskedascon128_958() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!(""),
      &hex!("BC820DBDF7A4631C5B29884AD69175C3389655CA8135C9E6E8FE7467276CA6C43D4C997E95731D91B0F015B769"),
    )
}

#[test]
fn test_maskedascon128_959() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("00"),
      &hex!("BD4640C4DA2FFA56DC79F7FDD07369DDF386CACC1CB31BF592F6AE1B443A809CAEBD10B0C5A0AF93A01B943C2C"),
    )
}

#[test]
fn test_maskedascon128_960() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("0001"),
      &hex!("6E9F820D5468A0D476620F58650864F0D5743BAA431BFDB037F8A32B9AC818C84CE87FCFC5B853A67157379C4E"),
    )
}

#[test]
fn test_maskedascon128_961() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102"),
      &hex!("F19D28E0F222B3BFCA11E151534C5CCC0BEFA1C3EF719C06CC916012F3A9F1D0FA90B2F5786F27706F51F35549"),
    )
}

#[test]
fn test_maskedascon128_962() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("00010203"),
      &hex!("7763F8BA6CE91ED1684F018AB62DF66F584D643B5BB5F3896A4C7440DA402CE7B7F2E4F19336E043D676CF9C7B"),
    )
}

#[test]
fn test_maskedascon128_963() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("0001020304"),
      &hex!("0E6A8B0CA517F53D3D72E1D8D734511C32CA4415FD432CB48AD6ADEBE7F126D948027B8AE222CA1C12285485CB"),
    )
}

#[test]
fn test_maskedascon128_964() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405"),
      &hex!("5B513546B1A1DC8AAAA010DC49CBA55351011507708E1F02193749927364F8A485BC8EC7D7C8AF4D0A0A9926D4"),
    )
}

#[test]
fn test_maskedascon128_965() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("00010203040506"),
      &hex!("2E5BBADE9599AC9F2D86F9D651791D72750FE31C291333ACCE97C4FB9E34E5F3692AB8943F6C2C3BE88D396421"),
    )
}

#[test]
fn test_maskedascon128_966() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("0001020304050607"),
      &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE457E42289AFB4317B2F4B6A9D90BE07F526414BD146DEF0EFE2985CB94"),
    )
}

#[test]
fn test_maskedascon128_967() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708"),
      &hex!("3225026599BCD4FCC460181575FA9D145BDD3D6B1B7332ED3D26467DCACAE26E836F57A32D624F058EADAA4F34"),
    )
}

#[test]
fn test_maskedascon128_968() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("00010203040506070809"),
      &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B15D9FF28142F6B7F25DF90E246E1D978BD9595956ABD90F022DB19559BB"),
    )
}

#[test]
fn test_maskedascon128_969() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A"),
      &hex!("76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD68FBFF1BECB97D75ACECB8F04FBF743F18E030F00B130"),
    )
}

#[test]
fn test_maskedascon128_970() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B"),
      &hex!("59B3A5338CD171F93D708C5B11AA14980574886B4C3921B84DB5A4A905FA2F483339F9CAEFAB2547806EB11D3A"),
    )
}

#[test]
fn test_maskedascon128_971() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C"),
      &hex!("8462C376C06AAE28BC182DF6B59467725A70FA80E6A3EBED6ADEF40D866EADAEB23B112EDD524DCB55B412347E"),
    )
}

#[test]
fn test_maskedascon128_972() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D"),
      &hex!("2E325340DF7FD0BFD25BEC2D8A596B4461B16D08AE54D9FB609FFC711C65A0DA61E24953ECBB15B3D3015F4E02"),
    )
}

#[test]
fn test_maskedascon128_973() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E"),
      &hex!("2E83CC36F088232A8EE9BAB74D02938E9DA2D9029331F558ED383557D1F1C497C1A8BDC2973E57C2EA59723B42"),
    )
}

#[test]
fn test_maskedascon128_974() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("1EE34125FDBA17443D01DA8A0EEFB04550CA93CE23A9DAAF0D7BDD7EB61C9E9D7357EC3441068F7FAD12A5CFAA"),
    )
}

#[test]
fn test_maskedascon128_975() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F10"),
      &hex!("8684539A9FCFF9F68A7A496010F129B5C9A3860BFF417050D0281D0BA8D4382C7553C5F3758FA1847BECDCDBF4"),
    )
}

#[test]
fn test_maskedascon128_976() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F1011"),
      &hex!("77AA511159627C4B855E67F95B3ABF1490F306CD374BC3B6C7BACE95ECFEE2D660A3F8CF4C0DBEA008FC2DAFB0"),
    )
}

#[test]
fn test_maskedascon128_977() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F101112"),
      &hex!("D323863E597297EAB51C8F134D3ED02E4EDBA0794BBA65739BDF24038A0905D8DF03C8768FF9636A56A3E22EA4"),
    )
}

#[test]
fn test_maskedascon128_978() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213"),
      &hex!("A31AC9A1D4D18222F332F245C70AB28D022B47C1D0D3135D34F55168C064488776A825541DBD6A5E7CE05460EA"),
    )
}

#[test]
fn test_maskedascon128_979() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
      &hex!("74EA9BA2635DCBAA400A5C24E4970400CA78DE82412D5B177C5DA6BE3F3F3DEFC64A1D35500C88B3E0B6DCADB7"),
    )
}

#[test]
fn test_maskedascon128_980() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
      &hex!("ADBB720C2D415EEC45978E6F894249E8ADE0A149F472B44C1D0E1E572CA10DEFE6C64FBFBCD781B881D29275B2"),
    )
}

#[test]
fn test_maskedascon128_981() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
      &hex!("3B29669395DAB8733301D70F21C844D9E7BA340F7DC44415E91AF7528C6866A2D130635DC6478A4BE9B9930853"),
    )
}

#[test]
fn test_maskedascon128_982() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
      &hex!("74A6A39D0A512958EE3091490331A6000BCB7389BBBFCC92C75A4D798EB2C6EBDD4DDBD44B03FB63C2A4AA38D6"),
    )
}

#[test]
fn test_maskedascon128_983() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
      &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB402824D3E8143C0875EB55B97DB059CC21C8E888CF864BE8E77F5E0BAD"),
    )
}

#[test]
fn test_maskedascon128_984() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
      &hex!("2D134D2DE994DEC27E6314484B8CA9FF75DC667993E0EE22C4CC8667767E565E10617F8E8E52EDCE82423F443F"),
    )
}

#[test]
fn test_maskedascon128_985() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("31686725B47CA995FC470C8F26199232AD6DEECA28E340E2E6D8AD601209CCAB1FCB68980666F34E0EC1BC893A"),
    )
}

#[test]
fn test_maskedascon128_986() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("C780135837218C32D20D3D705A15DB9B754566D10C5B9ECB22AAB461CEE32BA81DEB6176C029F7995617C0E6BB"),
    )
}

#[test]
fn test_maskedascon128_987() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("3BD2F45CE90E0F3731641C6EC79E1E39D04476081D37C89DA943AC8981B06E71A49D8B567DC2A0D5175FED0E7A"),
    )
}

#[test]
fn test_maskedascon128_988() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("270D846F99173380199972D19BE467B6C78B4088F95E422B2F1382ED85D5BBCD5C74DD8BA08B27FF9E36AA3E54"),
    )
}

#[test]
fn test_maskedascon128_989() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("D670F5A44971BE13F91BDD82E5152F149BFE1A1383E0F46BADA4B03BCF90B7C7E2556A0A93D394DD5E49EDE15E"),
    )
}

#[test]
fn test_maskedascon128_990() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("B96C78651B6246B0C3B1A5D373B0D5168DCA4A96734CF0DDF5F92F8D152CB136C4857754D15DFFF76B4681AD8A"),
    )
}

#[test]
fn test_maskedascon128_991() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!(""),
      &hex!("BC820DBDF7A4631C5B29884AD69175C3389655CA8135C9E6E8FE7467276FA645436E2F92D77DCBF1947C3061E759"),
    )
}

#[test]
fn test_maskedascon128_992() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("00"),
      &hex!("BD4640C4DA2FFA56DC79F7FDD07369DDF386CACC1CB31BF592F6AE1B44C70155F8EC67E9B87AEB68FA54A4C4FBFD"),
    )
}

#[test]
fn test_maskedascon128_993() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("0001"),
      &hex!("6E9F820D5468A0D476620F58650864F0D5743BAA431BFDB037F8A32B9A4BD7579920197AC5EEA45107010BE320E3"),
    )
}

#[test]
fn test_maskedascon128_994() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102"),
      &hex!("F19D28E0F222B3BFCA11E151534C5CCC0BEFA1C3EF719C06CC916012F34166A86BE0AB5543109BE0810068E0397B"),
    )
}

#[test]
fn test_maskedascon128_995() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("00010203"),
      &hex!("7763F8BA6CE91ED1684F018AB62DF66F584D643B5BB5F3896A4C7440DA6E2CBA448A0FD67B9DA55A9F63185AE6C6"),
    )
}

#[test]
fn test_maskedascon128_996() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("0001020304"),
      &hex!("0E6A8B0CA517F53D3D72E1D8D734511C32CA4415FD432CB48AD6ADEBE7630DA02FA2BD3D6787FAA3B1342C60BFE0"),
    )
}

#[test]
fn test_maskedascon128_997() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405"),
      &hex!("5B513546B1A1DC8AAAA010DC49CBA55351011507708E1F0219374992737A8F25A5355BF29C6E7BD2D6C945F9436B"),
    )
}

#[test]
fn test_maskedascon128_998() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("00010203040506"),
      &hex!("2E5BBADE9599AC9F2D86F9D651791D72750FE31C291333ACCE97C4FB9E9D3E81CE0B3431F8AE4036D63A462D85C8"),
    )
}

#[test]
fn test_maskedascon128_999() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("0001020304050607"),
      &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE457E42289AFB4317B2F4B6A9D92EC2939F5DA33F7E46CC2CAE4881D91411"),
    )
}

#[test]
fn test_maskedascon128_1000() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708"),
      &hex!("3225026599BCD4FCC460181575FA9D145BDD3D6B1B7332ED3D26467DCAC53FD6AADEC8D64472A6B869B8ACF37C46"),
    )
}

#[test]
fn test_maskedascon128_1001() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("00010203040506070809"),
      &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B15D9FF28142F6B7F25DF90E246E3B70F1D27203D9F3CBB2DB9E9E329FCB31"),
    )
}

#[test]
fn test_maskedascon128_1002() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A"),
      &hex!("76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD68FBFF1BECB975B0AF5F330C84765F019BEA2EA2F538862"),
    )
}

#[test]
fn test_maskedascon128_1003() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B"),
      &hex!("59B3A5338CD171F93D708C5B11AA14980574886B4C3921B84DB5A4A905AE906EA775A3A349A03092A6C6E110EBC2"),
    )
}

#[test]
fn test_maskedascon128_1004() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C"),
      &hex!("8462C376C06AAE28BC182DF6B59467725A70FA80E6A3EBED6ADEF40D867D2936CF04E0BE075BA122A9771DDEB668"),
    )
}

#[test]
fn test_maskedascon128_1005() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D"),
      &hex!("2E325340DF7FD0BFD25BEC2D8A596B4461B16D08AE54D9FB609FFC711C99EEB56C020B9A17376F09A6D76350A947"),
    )
}

#[test]
fn test_maskedascon128_1006() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E"),
      &hex!("2E83CC36F088232A8EE9BAB74D02938E9DA2D9029331F558ED383557D18A5603266F0ADDF6FA979C5616A14CC03D"),
    )
}

#[test]
fn test_maskedascon128_1007() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("1EE34125FDBA17443D01DA8A0EEFB04550CA93CE23A9DAAF0D7BDD7EB61BDCA8004E967CB004545D35E305FA03D2"),
    )
}

#[test]
fn test_maskedascon128_1008() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F10"),
      &hex!("8684539A9FCFF9F68A7A496010F129B5C9A3860BFF417050D0281D0BA8F4DB79F058E10F9B2621E9F1CBD925B041"),
    )
}

#[test]
fn test_maskedascon128_1009() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F1011"),
      &hex!("77AA511159627C4B855E67F95B3ABF1490F306CD374BC3B6C7BACE95EC2D1F774CAE6B92ACDC86D00DBFDC7BF5F9"),
    )
}

#[test]
fn test_maskedascon128_1010() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F101112"),
      &hex!("D323863E597297EAB51C8F134D3ED02E4EDBA0794BBA65739BDF24038A4AAF7576821E2746417E8B556F6E5635DB"),
    )
}

#[test]
fn test_maskedascon128_1011() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213"),
      &hex!("A31AC9A1D4D18222F332F245C70AB28D022B47C1D0D3135D34F55168C0CB3804042D1D3458C83451DB7F2A9E6CB0"),
    )
}

#[test]
fn test_maskedascon128_1012() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
      &hex!("74EA9BA2635DCBAA400A5C24E4970400CA78DE82412D5B177C5DA6BE3F2D1CE682F3AADCE160B13CB4B47538F2AE"),
    )
}

#[test]
fn test_maskedascon128_1013() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
      &hex!("ADBB720C2D415EEC45978E6F894249E8ADE0A149F472B44C1D0E1E572C565BFF0DC73F18939B77DB51E115796002"),
    )
}

#[test]
fn test_maskedascon128_1014() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
      &hex!("3B29669395DAB8733301D70F21C844D9E7BA340F7DC44415E91AF7528C588F41D1695E8A8F88079689FA0DD8C6FC"),
    )
}

#[test]
fn test_maskedascon128_1015() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
      &hex!("74A6A39D0A512958EE3091490331A6000BCB7389BBBFCC92C75A4D798E1AC8377BE10F3E9149A52217166BEA3152"),
    )
}

#[test]
fn test_maskedascon128_1016() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
      &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB402824D3E8143C0875EB55B97D3E21D93B1E974D02A0F99E0EFC46579924"),
    )
}

#[test]
fn test_maskedascon128_1017() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
      &hex!("2D134D2DE994DEC27E6314484B8CA9FF75DC667993E0EE22C4CC8667768148BCA22A0C2F15688387190B24B50851"),
    )
}

#[test]
fn test_maskedascon128_1018() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("31686725B47CA995FC470C8F26199232AD6DEECA28E340E2E6D8AD6012ED262EDF0264C2C59BC320F09B036F81F3"),
    )
}

#[test]
fn test_maskedascon128_1019() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("C780135837218C32D20D3D705A15DB9B754566D10C5B9ECB22AAB461CE95908AF22B272ABB7BF1FCF1CCC27E6F48"),
    )
}

#[test]
fn test_maskedascon128_1020() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("3BD2F45CE90E0F3731641C6EC79E1E39D04476081D37C89DA943AC8981517E90D4AD2411E7D1C4BE1DFB3C62A299"),
    )
}

#[test]
fn test_maskedascon128_1021() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("270D846F99173380199972D19BE467B6C78B4088F95E422B2F1382ED85A3AEF9E5770718A6B108C7D98BC70582CF"),
    )
}

#[test]
fn test_maskedascon128_1022() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("D670F5A44971BE13F91BDD82E5152F149BFE1A1383E0F46BADA4B03BCF8D39E70E374DD1222A6E455A32CEC3B933"),
    )
}

#[test]
fn test_maskedascon128_1023() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("B96C78651B6246B0C3B1A5D373B0D5168DCA4A96734CF0DDF5F92F8D15E3A57AA1BDD996FE335C3674061BF5740D"),
    )
}

#[test]
fn test_maskedascon128_1024() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!(""),
      &hex!("BC820DBDF7A4631C5B29884AD69175C3389655CA8135C9E6E8FE7467276F89B824D9C4AF5DA9337BA9AEC86C359A02"),
    )
}

#[test]
fn test_maskedascon128_1025() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("00"),
      &hex!("BD4640C4DA2FFA56DC79F7FDD07369DDF386CACC1CB31BF592F6AE1B44C716A97F9D4F7AEBB2389D65B69CFA2AEA2A"),
    )
}

#[test]
fn test_maskedascon128_1026() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("0001"),
      &hex!("6E9F820D5468A0D476620F58650864F0D5743BAA431BFDB037F8A32B9A4B8DFCDEAD9CEEA160DAEB1E0BA4C1EDA01E"),
    )
}

#[test]
fn test_maskedascon128_1027() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102"),
      &hex!("F19D28E0F222B3BFCA11E151534C5CCC0BEFA1C3EF719C06CC916012F341244329785B1DC1B38B2DC58AA105082128"),
    )
}

#[test]
fn test_maskedascon128_1028() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("00010203"),
      &hex!("7763F8BA6CE91ED1684F018AB62DF66F584D643B5BB5F3896A4C7440DA6E0BADB2E9E7465DDDEB9EADE2A7CB557346"),
    )
}

#[test]
fn test_maskedascon128_1029() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("0001020304"),
      &hex!("0E6A8B0CA517F53D3D72E1D8D734511C32CA4415FD432CB48AD6ADEBE7635B8F09B78EABF7294E856FFFE5E62BE74D"),
    )
}

#[test]
fn test_maskedascon128_1030() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405"),
      &hex!("5B513546B1A1DC8AAAA010DC49CBA55351011507708E1F0219374992737A53B58005A88C954E8838F23FA7934F29C2"),
    )
}

#[test]
fn test_maskedascon128_1031() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("00010203040506"),
      &hex!("2E5BBADE9599AC9F2D86F9D651791D72750FE31C291333ACCE97C4FB9E9DE0501463E5B74F7CC37063C6B7B22CBCDA"),
    )
}

#[test]
fn test_maskedascon128_1032() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("0001020304050607"),
      &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE457E42289AFB4317B2F4B6A9D92E72504EFFA6F2AB330A12D04BC91E59CBE3"),
    )
}

#[test]
fn test_maskedascon128_1033() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708"),
      &hex!("3225026599BCD4FCC460181575FA9D145BDD3D6B1B7332ED3D26467DCAC5F2C0F2623D54211261791BA6CF798F6299"),
    )
}

#[test]
fn test_maskedascon128_1034() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("00010203040506070809"),
      &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B15D9FF28142F6B7F25DF90E246E3BB0E67EDD562A075ECD2E7F23992DF723C5"),
    )
}

#[test]
fn test_maskedascon128_1035() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A"),
      &hex!("76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD68FBFF1BECB975BAD8DF3762BC14E321723B7725C816194E4"),
    )
}

#[test]
fn test_maskedascon128_1036() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B"),
      &hex!("59B3A5338CD171F93D708C5B11AA14980574886B4C3921B84DB5A4A905AE789427C037F2336FA220DECFBD8197B22D"),
    )
}

#[test]
fn test_maskedascon128_1037() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C"),
      &hex!("8462C376C06AAE28BC182DF6B59467725A70FA80E6A3EBED6ADEF40D867D4C18D9DDB4ADABB221863B0CB8C13CD1A1"),
    )
}

#[test]
fn test_maskedascon128_1038() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D"),
      &hex!("2E325340DF7FD0BFD25BEC2D8A596B4461B16D08AE54D9FB609FFC711C99775C280E44E5D89DE608B020C44BA09993"),
    )
}

#[test]
fn test_maskedascon128_1039() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E"),
      &hex!("2E83CC36F088232A8EE9BAB74D02938E9DA2D9029331F558ED383557D18AF5BC3D21AD2F0269C37C34086970D14856"),
    )
}

#[test]
fn test_maskedascon128_1040() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("1EE34125FDBA17443D01DA8A0EEFB04550CA93CE23A9DAAF0D7BDD7EB61BC5DDCAD91A1AC5D0D84D8B8804F2D48199"),
    )
}

#[test]
fn test_maskedascon128_1041() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F10"),
      &hex!("8684539A9FCFF9F68A7A496010F129B5C9A3860BFF417050D0281D0BA8F4B817F8CF3FD814F99F92665B6C532638DF"),
    )
}

#[test]
fn test_maskedascon128_1042() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F1011"),
      &hex!("77AA511159627C4B855E67F95B3ABF1490F306CD374BC3B6C7BACE95EC2DF1D01B7A5605DD551C7681DC91E0868832"),
    )
}

#[test]
fn test_maskedascon128_1043() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F101112"),
      &hex!("D323863E597297EAB51C8F134D3ED02E4EDBA0794BBA65739BDF24038A4A7A659779D7B9A164F05FE3859FD5B9F5B2"),
    )
}

#[test]
fn test_maskedascon128_1044() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213"),
      &hex!("A31AC9A1D4D18222F332F245C70AB28D022B47C1D0D3135D34F55168C0CB3B6A51C64E4824A249B047234B98F638A3"),
    )
}

#[test]
fn test_maskedascon128_1045() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
      &hex!("74EA9BA2635DCBAA400A5C24E4970400CA78DE82412D5B177C5DA6BE3F2D312C8341E1E9D0C1080342516CD3AEBA63"),
    )
}

#[test]
fn test_maskedascon128_1046() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
      &hex!("ADBB720C2D415EEC45978E6F894249E8ADE0A149F472B44C1D0E1E572C56936B67527E0B60FE59E250DBBC42366053"),
    )
}

#[test]
fn test_maskedascon128_1047() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
      &hex!("3B29669395DAB8733301D70F21C844D9E7BA340F7DC44415E91AF7528C58BA6878EC0D9DD471D03D42D923FDF172AA"),
    )
}

#[test]
fn test_maskedascon128_1048() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
      &hex!("74A6A39D0A512958EE3091490331A6000BCB7389BBBFCC92C75A4D798E1A29D888552E5D7345576D712B49DF1A4EC2"),
    )
}

#[test]
fn test_maskedascon128_1049() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
      &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB402824D3E8143C0875EB55B97D3ED247FFE495A80425C4DA73DC3D7786259A"),
    )
}

#[test]
fn test_maskedascon128_1050() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
      &hex!("2D134D2DE994DEC27E6314484B8CA9FF75DC667993E0EE22C4CC8667768182C81B3E5AD8E00AD448644F46A6CC24F1"),
    )
}

#[test]
fn test_maskedascon128_1051() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("31686725B47CA995FC470C8F26199232AD6DEECA28E340E2E6D8AD6012ED598C5E0330F4EFC73D77212CF52F35991A"),
    )
}

#[test]
fn test_maskedascon128_1052() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("C780135837218C32D20D3D705A15DB9B754566D10C5B9ECB22AAB461CE950B92025EA11556084B65F285E002089B8B"),
    )
}

#[test]
fn test_maskedascon128_1053() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("3BD2F45CE90E0F3731641C6EC79E1E39D04476081D37C89DA943AC898151750EFD11E9068C995D731A9BB2A30DC25B"),
    )
}

#[test]
fn test_maskedascon128_1054() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("270D846F99173380199972D19BE467B6C78B4088F95E422B2F1382ED85A342796EC881C7F63D271896E3355C13661E"),
    )
}

#[test]
fn test_maskedascon128_1055() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("D670F5A44971BE13F91BDD82E5152F149BFE1A1383E0F46BADA4B03BCF8D0DB702700281AE8EBA1B9A2384C77044F3"),
    )
}

#[test]
fn test_maskedascon128_1056() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("B96C78651B6246B0C3B1A5D373B0D5168DCA4A96734CF0DDF5F92F8D15E30278032E807419AC213C79CA3A5C4C0BFE"),
    )
}

#[test]
fn test_maskedascon128_1057() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!(""),
      &hex!("BC820DBDF7A4631C5B29884AD69175C3389655CA8135C9E6E8FE7467276F89770D975EFAB2EBAA41C0F3ABEEE425E784"),
    )
}

#[test]
fn test_maskedascon128_1058() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("00"),
      &hex!("BD4640C4DA2FFA56DC79F7FDD07369DDF386CACC1CB31BF592F6AE1B44C7168C1B3F4BF5810ED8FC586C8151954393ED"),
    )
}

#[test]
fn test_maskedascon128_1059() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("0001"),
      &hex!("6E9F820D5468A0D476620F58650864F0D5743BAA431BFDB037F8A32B9A4B8D5A10CD67506CBEBE3B8888198811646746"),
    )
}

#[test]
fn test_maskedascon128_1060() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102"),
      &hex!("F19D28E0F222B3BFCA11E151534C5CCC0BEFA1C3EF719C06CC916012F34124653B839DA8F4076B8A1A4BAD7B79ADC1E2"),
    )
}

#[test]
fn test_maskedascon128_1061() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("00010203"),
      &hex!("7763F8BA6CE91ED1684F018AB62DF66F584D643B5BB5F3896A4C7440DA6E0BF23C59A0B77D583FAEDF843D82A53C26BE"),
    )
}

#[test]
fn test_maskedascon128_1062() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("0001020304"),
      &hex!("0E6A8B0CA517F53D3D72E1D8D734511C32CA4415FD432CB48AD6ADEBE7635B2C9636CAB219E4127FC567A45440CA2369"),
    )
}

#[test]
fn test_maskedascon128_1063() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405"),
      &hex!("5B513546B1A1DC8AAAA010DC49CBA55351011507708E1F0219374992737A5326B1FD642E2BBB851EEF3E8775DD1DDBAA"),
    )
}

#[test]
fn test_maskedascon128_1064() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("00010203040506"),
      &hex!("2E5BBADE9599AC9F2D86F9D651791D72750FE31C291333ACCE97C4FB9E9DE02FCE1ED18D1533FCF96DAA6BCB9A4004A9"),
    )
}

#[test]
fn test_maskedascon128_1065() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("0001020304050607"),
      &hex!("69FFEE6F5505A4897E2EC80CBDFF67CE457E42289AFB4317B2F4B6A9D92E7244B7B19FFBD83AC4269C13DDF5D335F92C"),
    )
}

#[test]
fn test_maskedascon128_1066() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708"),
      &hex!("3225026599BCD4FCC460181575FA9D145BDD3D6B1B7332ED3D26467DCAC5F287400C7D741A64911990189440BA0C0716"),
    )
}

#[test]
fn test_maskedascon128_1067() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("00010203040506070809"),
      &hex!("3DDCE4DEABF18BBB4BF4EDACCE9A67B15D9FF28142F6B7F25DF90E246E3BB05E785F4E3E0E2FCE89B741827FDFE78E82"),
    )
}

#[test]
fn test_maskedascon128_1068() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A"),
      &hex!("76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD68FBFF1BECB975BADABF71505F48D2C6FE27850880318FF8197"),
    )
}

#[test]
fn test_maskedascon128_1069() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B"),
      &hex!("59B3A5338CD171F93D708C5B11AA14980574886B4C3921B84DB5A4A905AE78A5D7BBC174D80806FE7330701BE26F308C"),
    )
}

#[test]
fn test_maskedascon128_1070() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C"),
      &hex!("8462C376C06AAE28BC182DF6B59467725A70FA80E6A3EBED6ADEF40D867D4CE3996783B0A283DB2E4F7C8C24A551DB2D"),
    )
}

#[test]
fn test_maskedascon128_1071() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D"),
      &hex!("2E325340DF7FD0BFD25BEC2D8A596B4461B16D08AE54D9FB609FFC711C997781039A4632DC01EDF8CE7E67BFCDED66AD"),
    )
}

#[test]
fn test_maskedascon128_1072() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E"),
      &hex!("2E83CC36F088232A8EE9BAB74D02938E9DA2D9029331F558ED383557D18AF5FCDECADF4A755C36657D403191B0F4622B"),
    )
}

#[test]
fn test_maskedascon128_1073() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("1EE34125FDBA17443D01DA8A0EEFB04550CA93CE23A9DAAF0D7BDD7EB61BC53546073889CB92E4E846635199F7F294A9"),
    )
}

#[test]
fn test_maskedascon128_1074() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F10"),
      &hex!("8684539A9FCFF9F68A7A496010F129B5C9A3860BFF417050D0281D0BA8F4B8AAA418C1534CA1A6C18413253E0325E310"),
    )
}

#[test]
fn test_maskedascon128_1075() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F1011"),
      &hex!("77AA511159627C4B855E67F95B3ABF1490F306CD374BC3B6C7BACE95EC2DF15AB28BEF238CB709F96C8CF653DCF090E2"),
    )
}

#[test]
fn test_maskedascon128_1076() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112"),
      &hex!("D323863E597297EAB51C8F134D3ED02E4EDBA0794BBA65739BDF24038A4A7AE6F71B89F75605207014F635DAA35907BE"),
    )
}

#[test]
fn test_maskedascon128_1077() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213"),
      &hex!("A31AC9A1D4D18222F332F245C70AB28D022B47C1D0D3135D34F55168C0CB3B1DBE88E2FED76216E32191C2A9B5795F40"),
    )
}

#[test]
fn test_maskedascon128_1078() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
      &hex!("74EA9BA2635DCBAA400A5C24E4970400CA78DE82412D5B177C5DA6BE3F2D312860700C8E9CAB7DC4DD9602FFE433BCA3"),
    )
}

#[test]
fn test_maskedascon128_1079() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
      &hex!("ADBB720C2D415EEC45978E6F894249E8ADE0A149F472B44C1D0E1E572C5693F99296BBFA32AE24615BC60A6248AC856D"),
    )
}

#[test]
fn test_maskedascon128_1080() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
      &hex!("3B29669395DAB8733301D70F21C844D9E7BA340F7DC44415E91AF7528C58BA51EA51A5C50D971A9401C5FBA6F6BBA9D8"),
    )
}

#[test]
fn test_maskedascon128_1081() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
      &hex!("74A6A39D0A512958EE3091490331A6000BCB7389BBBFCC92C75A4D798E1A294285FCF2ACD4C7A44C365CF792E275D51D"),
    )
}

#[test]
fn test_maskedascon128_1082() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
      &hex!("2970E5D3DCDED18D81CD6C1F6BB2EDBB402824D3E8143C0875EB55B97D3ED299C7A774EC07F1E832BF1BB6BE383DE4E8"),
    )
}

#[test]
fn test_maskedascon128_1083() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
      &hex!("2D134D2DE994DEC27E6314484B8CA9FF75DC667993E0EE22C4CC8667768182683C0C60068563B5C68028A7A30ED3D668"),
    )
}

#[test]
fn test_maskedascon128_1084() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
      &hex!("31686725B47CA995FC470C8F26199232AD6DEECA28E340E2E6D8AD6012ED59FC87F6A67122323EF0F4BF5BE6CC34A067"),
    )
}

#[test]
fn test_maskedascon128_1085() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
      &hex!("C780135837218C32D20D3D705A15DB9B754566D10C5B9ECB22AAB461CE950BD2C1895752375586A0050E7B548AEE29E9"),
    )
}

#[test]
fn test_maskedascon128_1086() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
      &hex!("3BD2F45CE90E0F3731641C6EC79E1E39D04476081D37C89DA943AC89815175B262B9F07E152F2B8C6E22F50CCD0F03FD"),
    )
}

#[test]
fn test_maskedascon128_1087() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
      &hex!("270D846F99173380199972D19BE467B6C78B4088F95E422B2F1382ED85A34259AB59E243F2178B71D78AC5288F021DE8"),
    )
}

#[test]
fn test_maskedascon128_1088() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
      &hex!("D670F5A44971BE13F91BDD82E5152F149BFE1A1383E0F46BADA4B03BCF8D0D82347746A2CC5CF98AA1B919E67026E710"),
    )
}

#[test]
fn test_maskedascon128_1089() {
    run_tv::<MaskedAscon128>(
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
      &hex!("B96C78651B6246B0C3B1A5D373B0D5168DCA4A96734CF0DDF5F92F8D15E30270279BF6A6CC3F2FC9350B915C292BDB8D"),
    )
}
