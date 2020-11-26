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

let AES (key: seq<byte>) =
    use aes = Aes.Create()
    aes.Mode <- CipherMode.ECB
    aes.Key <- key |> Array.ofSeq
    aes.Padding <- PaddingMode.None
    aes
    
let decrypt key input =
    use aes = AES key
    let decryptor = aes.CreateDecryptor(aes.Key, aes.IV)
    let output = Array.create BLOCKSIZE 0uy
    decryptor.TransformBlock(input, 0, BLOCKSIZE, output, 0) |> ignore
    output |> Seq.ofArray

let decryptECB key input =
    input |> Seq.chunkBySize BLOCKSIZE |> Seq.map (decrypt key) |> Seq.concat
    
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

let AESDecryptCBC key iv ciphertext = AESCBC key iv ciphertext
let AESEncryptCBC key iv plaintext = AESCBC key iv (plaintext |> pkcs7pad BLOCKSIZE)
