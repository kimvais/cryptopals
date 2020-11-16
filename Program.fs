module Challenges
open Cryptopals.Utils


let c1 =

    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    input |> readHex |> base64encode |> printfn "%s"
    0

let getNumber (a: seq<string>): int = a |> Seq.head |> int

let selectChallenge c =
    match c with
    | 1 -> c1
    | _ -> 1

[<EntryPoint>]
let main argv = argv |> getNumber |> selectChallenge
