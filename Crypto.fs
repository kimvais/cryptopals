module Cryptopals.Crypto

open System.IO
open System.Security.Cryptography
open Cryptopals.Utils

[<Literal>]
let BLOCKSIZE = 16

let pkcs7pad (size: int) (input: seq<byte>) =
    let padlen = size - Seq.length input % size

    let padding = Seq.init padlen (fun _ -> byte padlen)

    Seq.concat [ input; padding ]
    
let getEncryptor (aes:Aes) = aes.CreateEncryptor()
let getDecryptor (aes:Aes) = aes.CreateDecryptor()

let AES (crypto) (mode: CipherMode) (key: seq<byte>) (input: seq<byte>) =
    use aes = Aes.Create()
    aes.Mode <- mode
    aes.Key <- key |> Array.ofSeq
    aes.Padding <- PaddingMode.None

    use inStream =
        new MemoryStream(input |> Array.ofSeq)

    use cryptoStream =
        new CryptoStream(inStream, crypto aes, CryptoStreamMode.Read)

    use outStream = new StreamReader(cryptoStream)
    outStream.ReadToEnd()

let Decrypt = AES getDecryptor
let Encrypt = AES getEncryptor

let AESBlock cipher key iv block =
    let result =
        cipher CipherMode.ECB key block
        |> Seq.map byte
        |> xorBytes iv
    // printfn "%s" <| bytesToStr result
    (result, block)

let AESCBC cipher (key: seq<byte>) (iv: seq<byte>) (input: seq<byte>) =
    input
    |> Seq.chunkBySize BLOCKSIZE
    |> Seq.map Seq.ofArray
    |> Seq.mapFold (AESBlock cipher key) iv
    |> fst |> Seq.concat

let AESDecryptCBC key iv ciphertext = AESCBC Decrypt key iv ciphertext
let AESEncryptCBC key iv plaintext = AESCBC Encrypt key iv (plaintext |> pkcs7pad BLOCKSIZE)
