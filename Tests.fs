module Cryptopals.Tests

open Xunit
open Xunit.Abstractions

open Cryptopals.Utils

type Set1(output:ITestOutputHelper) =
    let write result =
        output.WriteLine (sprintf "The result was %O" result)
        
    [<Fact>]
    let ``challenge 1``() =
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        let output = input |> readHex |> base64encode
        Assert.Equal(output, expected)

    [<Fact>]
    let ``challenge 2``() =
        let input = "1c0111001f010100061a024b53535009181c" |> readHex
        let key = "686974207468652062756c6c277320657965" |> readHex
        let expected = "746865206b696420646f6e277420706c6179"
        let output = xor key input
        Assert.Equal(output, expected)
        
    
    [<Fact>]
    let ``challenge 5``() =
        let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"  |> Seq.map byte
        let key = generateRepeatingKey "ICE"
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        let output = xor key input
        Assert.Equal(output, expected)