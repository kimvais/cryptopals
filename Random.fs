module Cryptopals.Random

open System
open System.Security.Cryptography


let rng = new RNGCryptoServiceProvider()
let prng = Random()

let getRandBytes n =
    let byteArray = Array.init (n) (fun _ -> (byte) 0)
    rng.GetBytes byteArray
    byteArray |> Seq.ofArray

let coinFlip =
    getRandBytes 1 |> (Seq.head >> int >> (>) 127)

