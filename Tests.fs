module Cryptopals.Tests

open Xunit
open Xunit.Abstractions

open Cryptopals.Utils

type Tests(output:ITestOutputHelper) =
    let write result =
        output.WriteLine (sprintf "The result was %O" result)
        
    [<Fact>]
    let ``challenge 1``() =
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        let output = input |> readHex |> base64encode
        Assert.Equal(output, expected)
