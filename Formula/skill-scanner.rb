class SkillScanner < Formula
  include Language::Python::Virtualenv

  desc "Security scanner for AI Agent Skills and MCP servers"
  homepage "https://github.com/cisco-ai-defense/skill-scanner"
  url "https://files.pythonhosted.org/packages/65/66/4dfb3b610799159d27dcb5b4dcb0f1aff739c2f27d159dedded844735229/cisco_ai_skill_scanner-2.3.1.tar.gz"
  sha256 "9d7f7ee5503a2694aab6f963203ded30976bfb36282217d12713cffbbacbc4f9"
  license "Apache-2.0"

  depends_on macos: :sonoma
  depends_on "go" => :build
  depends_on "python@3.12"

  # Prebuilt Rust extensions (jiter, litellm's bridge) carry @rpath install
  # names and no header room for Homebrew's absolute rewrite. Python loads
  # extension modules by path, so keep their IDs as built.
  preserve_rpath

  on_arm do
    resource "cel-helper" do
      url "https://files.pythonhosted.org/packages/21/c2/c48785204f56206ddc6c788782052a6cd6fce083f5941e7b095b5e40ee90/cisco_ai_skill_scanner-2.3.1-cp311.cp312.cp313.cp314-none-macosx_13_0_arm64.whl"
      sha256 "28a1e168d6b6af5d7615d6b157dccca551a68d59cc96952d0b21658349fd28ac"
    end
    resource "aiohappyeyeballs" do
      url "https://files.pythonhosted.org/packages/71/43/1947f06babed6b3f1d7f38b0c767f52df66bfb2bc10b468c4a7de9eceff2/aiohappyeyeballs-2.7.1-py3-none-any.whl", using: :nounzip
      sha256 "9243213661e29250eb41368e5daa826fc017156c3b8a11440826b2e3ed376472"
    end
    resource "aiohttp" do
      url "https://files.pythonhosted.org/packages/68/30/173960c42b05a6c59f7558e4b12a4b0d9ba376cf6aa9bde7f9e08a30ca8d/aiohttp-3.14.5-py3-none-any.whl", using: :nounzip
      sha256 "efc21a454892828368b11c2c780de0ff8bc991f73f6b99c6b66e56205470929b"
    end
    resource "aiosignal" do
      url "https://files.pythonhosted.org/packages/fb/76/641ae371508676492379f16e2fa48f4e2c11741bd63c48be4b12a6b09cba/aiosignal-1.4.0-py3-none-any.whl", using: :nounzip
      sha256 "053243f8b92b990551949e63930a839ff0cf0b0ebbe0597b0f3fb19e1a0fe82e"
    end
    resource "annotated-doc" do
      url "https://files.pythonhosted.org/packages/3e/30/e900b21425a860e195f32e37657aa1f7c7f2b1bfb26f03ca209b90933c06/annotated_doc-0.0.5-py3-none-any.whl", using: :nounzip
      sha256 "117bac03a25ede5df5440e855b32d556049ca169ead221505badf432fed4b101"
    end
    resource "annotated-types" do
      url "https://files.pythonhosted.org/packages/99/91/8acff4f5e50511b911bbccb72b8628a49c68ce14148cd9f6431094859a90/annotated_types-0.8.0-py3-none-any.whl", using: :nounzip
      sha256 "f072f4d804ea359e4eaf198b1af7a8b0943881a87f31bb764f8bf219bb9419e0"
    end
    resource "anthropic" do
      url "https://files.pythonhosted.org/packages/2f/1a/b1bd30cda3790557e8791bec5922a6ec8fabb6fa8b008c76a39cf7be6152/anthropic-0.125.0-py3-none-any.whl", using: :nounzip
      sha256 "3486013602eca76d8b12540764e53654f02cf4951110bca86cf06e67428a9f21"
    end
    resource "anyio" do
      url "https://files.pythonhosted.org/packages/12/b8/4bd346e22b28902df4d651910f5242c28d84e4a5c2435ca5c3f797ed7e2e/anyio-4.15.1-py3-none-any.whl", using: :nounzip
      sha256 "6152fdbbf9a77fdec97731721bebf7c4c44f7c29b424b0065826173efc7ed101"
    end
    resource "attrs" do
      url "https://files.pythonhosted.org/packages/64/b4/17d4b0b2a2dc85a6df63d1157e028ed19f90d4cd97c36717afef2bc2f395/attrs-26.1.0-py3-none-any.whl", using: :nounzip
      sha256 "c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309"
    end
    resource "boto3" do
      url "https://files.pythonhosted.org/packages/78/de/cf71466f55516e61d8048374776b390a036a1b48c9a7a4cd8e21f8b27980/boto3-1.43.116-py3-none-any.whl", using: :nounzip
      sha256 "9dca4dbd464b189041b27b5a02280bd5e02c3051bebf6bd03cd0e47aaf558030"
    end
    resource "botocore" do
      url "https://files.pythonhosted.org/packages/3e/2e/449851ffdd5c6cd521d309bba501077025929ba0ef005a3052f43fca509e/botocore-1.43.116-py3-none-any.whl", using: :nounzip
      sha256 "92f1efe8434183f08f91a61478925f5f8d23082024556f269f916477040e26f4"
    end
    resource "certifi" do
      url "https://files.pythonhosted.org/packages/c4/51/29046e48f693c54e5b7412216d447a1d8362c9653148d98c02cdf65fa733/certifi-2026.10.19-py3-none-any.whl", using: :nounzip
      sha256 "42d35340cc5b9ba78e818ddbff0c5b1c2b779de448a340fd1b989f5fa8670e1b"
    end
    resource "cffi" do
      url "https://files.pythonhosted.org/packages/54/7d/16e5a096677b5e313ca80cd5e5170efa3ea44624a82bb111925522da64b1/cffi-2.1.1-cp312-cp312-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "f81b3b8f3d4e343550fa4baa0e479bba9f2d29ce9c2e9b51d1ce1718d7442fcf"
    end
    resource "charset-normalizer" do
      url "https://files.pythonhosted.org/packages/fc/ad/d07d7862a62ffa6d79d68074d14823243dd235a77c45262acbf6adeb28bf/charset_normalizer-3.5.2-py3-none-any.whl", using: :nounzip
      sha256 "b6b751274acb69d77b3323d6b7dbaa3c7fdfc1eb829b7eb61d262f32e1af9685"
    end
    resource "click" do
      url "https://files.pythonhosted.org/packages/58/50/6c0d534c5f134586a8e1ba4e330569e32f057e33372ae556463212fb4cd3/click-8.5.0-py3-none-any.whl", using: :nounzip
      sha256 "255bc9599cf7748b4b1a446ccc735421bd08a2ae529a8b88597d3de5664ee360"
    end
    resource "colorclass" do
      url "https://files.pythonhosted.org/packages/30/b6/daf3e2976932da4ed3579cff7a30a53d22ea9323ee4f0d8e43be60454897/colorclass-2.2.2-py2.py3-none-any.whl", using: :nounzip
      sha256 "6f10c273a0ef7a1150b1120b6095cbdd68e5cf36dfd5d0fc957a2500bbf99a55"
    end
    resource "confusable-homoglyphs" do
      url "https://files.pythonhosted.org/packages/c5/6e/c0fcbb7d341a46cf4241a6aa9e6a737734f0657521fc1bcd074953fe4eea/confusable_homoglyphs-3.3.1-py2.py3-none-any.whl", using: :nounzip
      sha256 "84c92cb79dc7f55aa290d0762b2349abd8dee4c16fbe6f99eac978d394e2e6a1"
    end
    resource "cryptography" do
      url "https://files.pythonhosted.org/packages/e5/56/d194340cc4a57535e82e1bee9e89667ac4b7c13b5d3f59686deae3094dd5/cryptography-50.0.2-cp311-abi3-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "fa8f5efb344d6908a1ce62f4a24e2e5780f825d6f53f5f50ec5ffacac72936cb"
    end
    resource "distro" do
      url "https://files.pythonhosted.org/packages/12/b3/231ffd4ab1fc9d679809f356cebee130ac7daa00d6d6f3206dd4fd137e9e/distro-1.9.0-py3-none-any.whl", using: :nounzip
      sha256 "7bffd925d65168f85027d8da9af6bddab658135b840670a223589bc0c8ef02b2"
    end
    resource "docstring-parser" do
      url "https://files.pythonhosted.org/packages/a7/5f/ed01f9a3cdffbd5a008556fc7b2a08ddb1cc6ace7effa7340604b1d16699/docstring_parser-0.18.0-py3-none-any.whl", using: :nounzip
      sha256 "b3fcbed555c47d8479be0796ef7e19c2670d428d72e96da63f3a40122860374b"
    end
    resource "easygui" do
      url "https://files.pythonhosted.org/packages/8e/a7/b276ff776533b423710a285c8168b52551cb2ab0855443131fdc7fd8c16f/easygui-0.98.3-py2.py3-none-any.whl", using: :nounzip
      sha256 "33498710c68b5376b459cd3fc48d1d1f33822139eb3ed01defbc0528326da3ba"
    end
    resource "fastapi" do
      url "https://files.pythonhosted.org/packages/50/c3/759716158338892ed8e483077241cdf80e1fd727f56baf750c75bfea58de/fastapi-0.157.0-py3-none-any.whl", using: :nounzip
      sha256 "45b5cbf098ce3f47e008ca67931ce333d028129c823e3b6766a3bd0d70b81f7f"
    end
    resource "fastuuid" do
      url "https://files.pythonhosted.org/packages/02/a2/e78fcc5df65467f0d207661b7ef86c5b7ac62eea337c0c0fcedbeee6fb13/fastuuid-0.14.0-cp312-cp312-macosx_10_12_x86_64.macosx_11_0_arm64.macosx_10_12_universal2.whl", using: :nounzip
      sha256 "77e94728324b63660ebf8adb27055e92d2e4611645bf12ed9d88d30486471d0a"
    end
    resource "filelock" do
      url "https://files.pythonhosted.org/packages/15/df/31098c5aeb4d966b553641472bd55fcf5fdfac953549894b8a765ba44e91/filelock-3.32.7-py3-none-any.whl", using: :nounzip
      sha256 "65ff0d0190ea42038b32bda4b77834fb05be2cad4c5b9b01aa4dfb3614536e52"
    end
    resource "flatbuffers" do
      url "https://files.pythonhosted.org/packages/e8/2d/d2a548598be01649e2d46231d151a6c56d10b964d94043a335ae56ea2d92/flatbuffers-25.12.19-py2.py3-none-any.whl", using: :nounzip
      sha256 "7634f50c427838bb021c2d66a3d1168e9d199b0607e6329399f04846d42e20b4"
    end
    resource "frozenlist" do
      url "https://files.pythonhosted.org/packages/9a/9a/e35b4a917281c0b8419d4207f4334c8e8c5dbf4f3f5f9ada73958d937dcc/frozenlist-1.8.0-py3-none-any.whl", using: :nounzip
      sha256 "0c18a16eab41e82c295618a77502e17b195883241c563b00f0aa5106fc4eaa0d"
    end
    resource "fsspec" do
      url "https://files.pythonhosted.org/packages/6c/c0/a98505f18594f1bce828bb159cec0fcf9860562f1a2c85913409fc8f3d9e/fsspec-2026.9.0-py3-none-any.whl", using: :nounzip
      sha256 "8dd6e646e99ea382bd85f97a45e6b526a442d79423a7dc673f1e2756d05fcb5f"
    end
    resource "h11" do
      url "https://files.pythonhosted.org/packages/04/4b/29cac41a4d98d144bf5f6d33995617b185d14b22401f75ca86f384e87ff1/h11-0.16.0-py3-none-any.whl", using: :nounzip
      sha256 "63cf8bbe7522de3bf65932fda1d9c2772064ffb3dae62d55932da54b31cb6c86"
    end
    resource "h2" do
      url "https://files.pythonhosted.org/packages/7e/22/e85faf23bd72a92d1921e37d674ca56eb298a3c8be31fdecef0ff2b3aaac/h2-4.4.1-py3-none-any.whl", using: :nounzip
      sha256 "0e25f1462b23c9cb82d9eb02e28bc706dac2a68cb457c6a0d74d63c8a2a5d0e6"
    end
    resource "hatch-vcs" do
      url "https://files.pythonhosted.org/packages/5f/48/1f85cee4b7b4f40b9b814b1febbc661bda6ced9649e410a0b74f6e415dd0/hatch_vcs-0.5.0-py3-none-any.whl", using: :nounzip
      sha256 "b49677dbdc597460cc22d01b27ab3696f5e16a21ecf2700fb01bc28e1f2a04a7"
    end
    resource "hatchling" do
      url "https://files.pythonhosted.org/packages/5f/80/91f51f439c05d4ec4623c22928ce16a938d6d793bf709477830823497859/hatchling-1.32.4-py3-none-any.whl", using: :nounzip
      sha256 "08ecf7548fb48205e7f213d70c71e67b8271b7242093dc3f1da578b42c734a2c"
    end
    resource "hf-xet" do
      url "https://files.pythonhosted.org/packages/c3/47/a26ebdce7056a61e931f228439bc0ab08cbec239d1690f965e5e637cba79/hf_xet-1.7.0-cp38-abi3-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "59fba37039233c7fcbe196817d6cdcf1b40dfb17b410f229d85b0cf0a1848da4"
    end
    resource "hpack" do
      url "https://files.pythonhosted.org/packages/71/b4/4a9fcfb2aef6ba44d9073ecd301443aa00b3dac95de5619f2a7de7ec8a91/hpack-4.2.0-py3-none-any.whl", using: :nounzip
      sha256 "858ac0b02280fa582b5080d68db0899c62a80375e0e5413a74970c5e518b6986"
    end
    resource "httpcore" do
      url "https://files.pythonhosted.org/packages/7e/f5/f66802a942d491edb555dd61e3a9961140fd64c90bce1eafd741609d334d/httpcore-1.0.9-py3-none-any.whl", using: :nounzip
      sha256 "2d400746a40668fc9dec9810239072b40b4484b640a8c38fd654a024c7a1bf55"
    end
    resource "httptools" do
      url "https://files.pythonhosted.org/packages/da/ed/0916b8b7ebd1deeaf22acba71b68c57b4b6b69aa1918f3812dea208b4276/httptools-0.9.0-cp312-cp312-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "f9ccc9884241efceb4547a92955d128574c864681f11b7ea3ecbde295fafbe8b"
    end
    resource "httpx" do
      url "https://files.pythonhosted.org/packages/2a/39/e50c7c3a983047577ee07d2a9e53faf5a69493943ec3f6a384bdc792deb2/httpx-0.28.1-py3-none-any.whl", using: :nounzip
      sha256 "d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad"
    end
    resource "huggingface-hub" do
      url "https://files.pythonhosted.org/packages/fc/16/963096d224b80909432dc16561a615fd33d2d13beef3ce4c63fa25e40867/huggingface_hub-1.33.0-py3-none-any.whl", using: :nounzip
      sha256 "04e434b06e100eddbce9a6e817d72693a7884b10a79bd67ab48080d5c07eb899"
    end
    resource "hyperframe" do
      url "https://files.pythonhosted.org/packages/48/30/47d0bf6072f7252e6521f3447ccfa40b421b6824517f82854703d0f5a98b/hyperframe-6.1.0-py3-none-any.whl", using: :nounzip
      sha256 "b03380493a519fce58ea5af42e4a42317bf9bd425596f7a0835ffce80f1a42e5"
    end
    resource "idna" do
      url "https://files.pythonhosted.org/packages/58/a2/bb081bab032533a855d44de1d56f8e8426114ff1ba5d1f07a438a0a654f8/idna-3.20-py3-none-any.whl", using: :nounzip
      sha256 "ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c"
    end
    resource "importlib-metadata" do
      url "https://files.pythonhosted.org/packages/7d/f9/97f2ca8bb3ec6e4b1d64f983ebe98b9a192faddff67fac3d6303a537e670/importlib_metadata-8.9.0-py3-none-any.whl", using: :nounzip
      sha256 "e0f761b6ea91ced3b0844c14c9d955224d538105921f8e6754c00f6ca79fba7f"
    end
    resource "Jinja2" do
      url "https://files.pythonhosted.org/packages/62/a1/3d680cbfd5f4b8f15abc1d571870c5fc3e594bb582bc3b64ea099db13e56/jinja2-3.1.6-py3-none-any.whl", using: :nounzip
      sha256 "85ece4451f492d0c13c5dd7c13a64681a86afae63a5f347908daf103ce6d2f67"
    end
    resource "jiter" do
      url "https://files.pythonhosted.org/packages/0e/5e/0de4c6f84ffefa6809ffc2d550b9a314365acf7e7ec9b6c7375d49047900/jiter-0.17.0-cp312-cp312-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "61aed66ee042b3b49ef85fdf75714234d055d89d8496ac1c6e47f89e7a30d5e4"
    end
    resource "jmespath" do
      url "https://files.pythonhosted.org/packages/14/2f/967ba146e6d58cf6a652da73885f52fc68001525b4197effc174321d70b4/jmespath-1.1.0-py3-none-any.whl", using: :nounzip
      sha256 "a5663118de4908c91729bea0acadca56526eb2698e83de10cd116ae0f4e97c64"
    end
    resource "jsonschema" do
      url "https://files.pythonhosted.org/packages/69/90/f63fb5873511e014207a475e2bb4e8b2e570d655b00ac19a9a0ca0a385ee/jsonschema-4.26.0-py3-none-any.whl", using: :nounzip
      sha256 "d489f15263b8d200f8387e64b4c3a75f06629559fb73deb8fdfb525f2dab50ce"
    end
    resource "jsonschema-specifications" do
      url "https://files.pythonhosted.org/packages/41/45/1a4ed80516f02155c51f51e8cedb3c1902296743db0bbc66608a0db2814f/jsonschema_specifications-2025.9.1-py3-none-any.whl", using: :nounzip
      sha256 "98802fee3a11ee76ecaca44429fda8a41bff98b00a0f2838151b113f210cc6fe"
    end
    resource "linkify-it-py" do
      url "https://files.pythonhosted.org/packages/13/d4/1152d1c7ab42d8b908be64fd200ddc870dc9d4925e951198702084aa1a7d/linkify_it_py-2.2.0-py3-none-any.whl", using: :nounzip
      sha256 "3adc40eb5af300b2605fcfdb968c24e1d780a90f1f2221af7c15e5111e94d443"
    end
    resource "litellm" do
      url "https://files.pythonhosted.org/packages/51/fc/15e44b2a222dfda71e0aff107fccfb49b06a4695fae0eb6867aff84f7e1d/litellm-1.106.2-cp310-abi3-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "cc778d01ed65a8dd57d5211d581ec237e06df239a09c3d573ace33e0feea76c9"
    end
    resource "magika" do
      url "https://files.pythonhosted.org/packages/93/eb/24d94db0530029649b266ec3ca8221c07f2754f56046181f13237d2518f5/magika-1.0.3-py3-none-any.whl", using: :nounzip
      sha256 "938d8e033953f2ddeb8c35dc423aa289ca116bfa7a71a778f6e77460f9025803"
    end
    resource "markdown-it-py" do
      url "https://files.pythonhosted.org/packages/b3/81/4da04ced5a082363ecfa159c010d200ecbd959ae410c10c0264a38cac0f5/markdown_it_py-4.2.0-py3-none-any.whl", using: :nounzip
      sha256 "9f7ebbcd14fe59494226453aed97c1070d83f8d24b6fc3a3bcf9a38092641c4a"
    end
    resource "MarkupSafe" do
      url "https://files.pythonhosted.org/packages/a2/f0/d6613774d86fbf6d145751d43c59875e47a6f9f17daee0aef173bd36d90e/markupsafe-3.0.4-cp312-cp312-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "0930db9bdc62d22944e10b066448bb65dc9abe9112880c7cab8da54db4284d5f"
    end
    resource "mdit-py-plugins" do
      url "https://files.pythonhosted.org/packages/a5/69/6da5581c6a7fede7dc261bf4e67d6adca4196f176b43288b55b3db395b6e/mdit_py_plugins-0.6.1-py3-none-any.whl", using: :nounzip
      sha256 "214c82fb2ac524472ab6a5bcab1de80f73b50443e187f401bfd77efbc7c6481d"
    end
    resource "mdurl" do
      url "https://files.pythonhosted.org/packages/b3/38/89ba8ad64ae25be8de66a6d463314cf1eb366222074cfda9ee839c56a4b4/mdurl-0.1.2-py3-none-any.whl", using: :nounzip
      sha256 "84008a41e51615a49fc9966191ff91509e3c40b939176e643fd50a5c2196b8f8"
    end
    resource "msoffcrypto-tool" do
      url "https://files.pythonhosted.org/packages/3c/85/9e359fa9279e1d6861faaf9b6f037a3226374deb20a054c3937be6992013/msoffcrypto_tool-6.0.0-py3-none-any.whl", using: :nounzip
      sha256 "46c394ed5d9641e802fc79bf3fb0666a53748b23fa8c4aa634ae9d30d46fe397"
    end
    resource "multidict" do
      url "https://files.pythonhosted.org/packages/d0/86/a3de309c5e28ee85b314d0e3ba0e0dea6fd361c313322a05e67be4656e1e/multidict-7.1.0-py3-none-any.whl", using: :nounzip
      sha256 "d9ef29cfd98e17085b4f91bba8fa1570bec6787d5c52ce653ed33a58785585d0"
    end
    resource "numpy" do
      url "https://files.pythonhosted.org/packages/ff/a9/bac826765e971d8e16e2064e9ac7525fd69b40ac17c905033a7f5442023f/numpy-2.5.4-cp312-cp312-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "b11e8fda06a7d69f15ebf542660b74466c2e51094800c1fb794f47ad4faeef17"
    end
    resource "olefile" do
      url "https://files.pythonhosted.org/packages/17/d3/b64c356a907242d719fc668b71befd73324e47ab46c8ebbbede252c154b2/olefile-0.47-py2.py3-none-any.whl", using: :nounzip
      sha256 "543c7da2a7adadf21214938bb79c83ea12b473a4b6ee4ad4bf854e7715e13d1f"
    end
    resource "oletools" do
      url "https://files.pythonhosted.org/packages/ac/ff/05257b7183279b80ecec6333744de23f48f0faeeba46c93e6d13ce835515/oletools-0.60.2-py2.py3-none-any.whl", using: :nounzip
      sha256 "72ad8bd748fd0c4e7b5b4733af770d11543ebb2bf2697455f99f975fcd50cc96"
    end
    resource "onnxruntime" do
      url "https://files.pythonhosted.org/packages/b3/bd/2ac094311163b803e3626c3937461d6900934bd56cca7601f6150ff860c3/onnxruntime-1.31.0-cp312-cp312-macosx_14_0_arm64.whl", using: :nounzip
      sha256 "aaab9b3af536b06ca27ab5e35e3d429c97457ce76cf298af103f687e8b9975c0"
    end
    resource "openai" do
      url "https://files.pythonhosted.org/packages/64/a8/bb76c7356de8ad57f59d5ff993d434df0607f07f08bcc9c9a5c275e399c0/openai-2.54.0-py3-none-any.whl", using: :nounzip
      sha256 "89089789197ccdb87f173a03145ed1598d00795220c93e96cf712b1cbf5e5f2b"
    end
    resource "opentelemetry-api" do
      url "https://files.pythonhosted.org/packages/1e/41/f7dcf80b81ee8e71c1a2b59f14208bc723edbd89ed027a73b175abf6348e/opentelemetry_api-1.45.1-py3-none-any.whl", using: :nounzip
      sha256 "b31553efa588ae44bc306f863c785c5333a9ecc091248c6ee68b4b6c87fdedfb"
    end
    resource "packaging" do
      url "https://files.pythonhosted.org/packages/63/34/ba1c580383c9eada3711951fef0795c80b829a078d72188184bcab9dd527/packaging-26.3-py3-none-any.whl", using: :nounzip
      sha256 "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c"
    end
    resource "pathspec" do
      url "https://files.pythonhosted.org/packages/f1/d9/7fb5aa316bc299258e68c73ba3bddbc499654a07f151cba08f6153988714/pathspec-1.1.1-py3-none-any.whl", using: :nounzip
      sha256 "a00ce642f577bf7f473932318056212bc4f8bfdf53128c78bbd5af0b9b20b189"
    end
    resource "pcodedmp" do
      url "https://files.pythonhosted.org/packages/ba/72/b380fb5c89d89c3afafac8cf02a71a45f4f4a4f35531ca949a34683962d1/pcodedmp-1.2.6-py2.py3-none-any.whl", using: :nounzip
      sha256 "4441f7c0ab4cbda27bd4668db3b14f36261d86e5059ce06c0828602cbe1c4278"
    end
    resource "pdfid" do
      url "https://files.pythonhosted.org/packages/29/48/9ba402d773ffac76515720f98f3a01a2802737b6a2b75cac1fb8ba269a7a/pdfid-1.1.3-py3-none-any.whl", using: :nounzip
      sha256 "9b9b72145a81759c6e9f327eb0e115a30a3fbd140fa5bd5da0d1956ec4c9f65a"
    end
    resource "platformdirs" do
      url "https://files.pythonhosted.org/packages/6c/8a/1d8cb3842909dc193a73835adedf412e32e18f8ffd59f43983949622fe6f/platformdirs-4.13.5-py3-none-any.whl", using: :nounzip
      sha256 "53d3ec4280b815c1e0b02edad7f9ee8fda1ba9c0865dd9c2e6e63849ce82fc1e"
    end
    resource "pluggy" do
      url "https://files.pythonhosted.org/packages/40/9e/2b38731e0fc536806f16490e1a12d7f0dc2a1235aa8cc07bcc75416a7daa/pluggy-1.7.0-py3-none-any.whl", using: :nounzip
      sha256 "7dd7b0d8832ba3cb632c306926ded123429211b83641b35dc5c41ad2d34f9bec"
    end
    resource "propcache" do
      url "https://files.pythonhosted.org/packages/f5/cd/785c64ed382f3f04201870267b02783f63b4678c2acfddc177a3ebcc2727/propcache-0.5.4-py3-none-any.whl", using: :nounzip
      sha256 "62c60aec739ed00124573cce1178138fd690c7676352d67a37328c1cf51d7468"
    end
    resource "protobuf" do
      url "https://files.pythonhosted.org/packages/c4/72/02445137af02769918a93807b2b7890047c32bfb9f90371cbc12688819eb/protobuf-6.33.6-py3-none-any.whl", using: :nounzip
      sha256 "77179e006c476e69bf8e8ce866640091ec42e1beb80b213c3900006ecfba6901"
    end
    resource "pycparser" do
      url "https://files.pythonhosted.org/packages/90/11/0e6f11117525ff0eec40ebac3d313376f102df93ca44ad9e893ee85e4f89/pycparser-3.11-py3-none-any.whl", using: :nounzip
      sha256 "51d5a8ba2be0bbe440b99d2112604c95bbbc3c2748a64260186c541e1729cd80"
    end
    resource "pydantic" do
      url "https://files.pythonhosted.org/packages/35/ea/a56b9fe5066f3537b7882f77e9c5dfb26d8c2eefdaed9b5fc73d57b4dc22/pydantic-2.14.1-py3-none-any.whl", using: :nounzip
      sha256 "9195d967ec791692a04438115466764fb8b9a27b31f14a760437694f40d6b454"
    end
    resource "pydantic_core" do
      url "https://files.pythonhosted.org/packages/db/a3/f8b1b39349c33037c73d7a1b794c9c29d8f07d5bd2b74399c1375a529cc6/pydantic_core-2.50.1-cp312-cp312-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "e8e1d6ce820aa23317e8209a86bd65a540973c12dc7552b48a4f6c8e9926815e"
    end
    resource "pydantic-settings" do
      url "https://files.pythonhosted.org/packages/3c/74/fdf926afe145d8629c4b2ff57f4ea1d64ed7abc4d84d97463b2517a2547e/pydantic_settings-2.16.1-py3-none-any.whl", using: :nounzip
      sha256 "30f5313340da4e8f1b440d1910b92a5bc3ccbb6b4ba70ec2b8395bc921f418f5"
    end
    resource "Pygments" do
      url "https://files.pythonhosted.org/packages/71/46/17f022dd3e953bf20a04a028a21ec746d942f8d2af30fa0f124fa0e6a684/pygments-2.21.0-py3-none-any.whl", using: :nounzip
      sha256 "2363c69b61c4a97c838da3b130dcd6468f4848992b21a82f2a63ec34377137d9"
    end
    resource "PyJWT" do
      url "https://files.pythonhosted.org/packages/50/ca/44de4e75f8aadc457f0634be3b542815078ded46dca30efb960edeecad6e/pyjwt-2.15.1-py3-none-any.whl", using: :nounzip
      sha256 "42d59d631f7768a1028a64c7ff581a9bf7519804daf91fc5b6c56e30eec5e193"
    end
    resource "pyparsing" do
      url "https://files.pythonhosted.org/packages/38/bb/d215ee7c73b61497b28a5503f9f53523f294fcc936762b7caf90e0c1c2b5/pyparsing-3.3.3-py3-none-any.whl", using: :nounzip
      sha256 "ece8c00a69cf01b45d0b1dedabb469c90d8caf996d4fda40f147627a122849a4"
    end
    resource "python-dateutil" do
      url "https://files.pythonhosted.org/packages/ec/57/56b9bcc3c9c6a792fcbaf139543cee77261f3651ca9da0c93f5c1221264b/python_dateutil-2.9.0.post0-py2.py3-none-any.whl", using: :nounzip
      sha256 "a8b2bc7bffae282281c8140a97d3aa9c14da0b136dfe83f850eea9a5f7470427"
    end
    resource "python-dotenv" do
      url "https://files.pythonhosted.org/packages/60/d1/38f3a3405989a89ac18390803e70c6ad7c7760da4f9b83cbeca0c44a0c72/python_dotenv-1.2.4-py3-none-any.whl", using: :nounzip
      sha256 "42269a8a5b3fd54ffa6f3d84b18abed50064717576b4ecf03dc4a55d8aa04fdc"
    end
    resource "python-frontmatter" do
      url "https://files.pythonhosted.org/packages/a6/a3/17c284b4f4d8ad50f0f9ba70ad8fcc35c777aeafcdbbffdd91bbdc5ab379/python_frontmatter-1.3.0-py3-none-any.whl", using: :nounzip
      sha256 "9f7dd9260bec99044219159a329f64f039087f9d1a2124c9442556f2fe6f82ec"
    end
    resource "python-multipart" do
      url "https://files.pythonhosted.org/packages/e1/04/e8135ebd1ad02c56ec633277529b2602ff99ff634be76cdba5744cf554fd/python_multipart-0.0.32-py3-none-any.whl", using: :nounzip
      sha256 "ff6d3f776f16878c894e52e107296ffc890e913c611b1a4ec6c44e2821fe2e23"
    end
    resource "PyYAML" do
      url "https://files.pythonhosted.org/packages/89/a0/6cf41a19a1f2f3feab0e9c0b74134aa2ce6849093d5517a0c550fe37a648/pyyaml-6.0.3-cp312-cp312-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "fc09d0aa354569bc501d4e787133afc08552722d3ab34836a80547331bb5d4a0"
    end
    resource "referencing" do
      url "https://files.pythonhosted.org/packages/2c/58/ca301544e1fa93ed4f80d724bf5b194f6e4b945841c5bfd555878eea9fcb/referencing-0.37.0-py3-none-any.whl", using: :nounzip
      sha256 "381329a9f99628c9069361716891d34ad94af76e461dcb0335825aecc7692231"
    end
    resource "regex" do
      url "https://files.pythonhosted.org/packages/84/48/3fdcde9a0baa84d7d25571223265d6e434e114763b438601d54a8028bf3e/regex-2026.9.29-cp312-cp312-macosx_10_13_universal2.whl", using: :nounzip
      sha256 "dc79d36d0618752265f0d575915bdc5c5130ecb9c9f6b3bcefeae32e4bdfafcf"
    end
    resource "requests" do
      url "https://files.pythonhosted.org/packages/a0/f4/c67b0b3f1b9245e8d266f0f112c500d50e5b4e83cb6f3b71b6528104182a/requests-2.34.2-py3-none-any.whl", using: :nounzip
      sha256 "2a0d60c172f83ac6ab31e4554906c0f3b3588d37b5cb939b1c061f4907e278e0"
    end
    resource "rich" do
      url "https://files.pythonhosted.org/packages/b3/76/6d163cfac87b632216f71879e6b2cf17163f773ff59c00b5ff4900a80fa3/rich-14.3.4-py3-none-any.whl", using: :nounzip
      sha256 "07e7adb4690f68864777b1450859253bed81a99a31ac321ac1817b2313558952"
    end
    resource "rpds-py" do
      url "https://files.pythonhosted.org/packages/90/81/ac6a0d064982251856ce009c9e1dd51a34110b3c055aa7d1aad18b4899a3/rpds_py-2026.9.1-cp312-cp312-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "e21c1429e205828ea886a2293a4a2c8e01f4c25d9893ca330e97a6cf73f52e7b"
    end
    resource "s3transfer" do
      url "https://files.pythonhosted.org/packages/e2/a4/88f9e10498759121060b8050a1554753dfc04df39bbbcc7aad9ecc8d9440/s3transfer-0.19.3-py3-none-any.whl", using: :nounzip
      sha256 "24eb7535804306355e31c952a90022bf5b2f9d760f9a11062c7493a217c08553"
    end
    resource "setuptools" do
      url "https://files.pythonhosted.org/packages/ef/55/6dc6d6bb953bdfc52519a0059592c52b6e3b8ad51cf8256dffceb55b0610/setuptools-84.2.1-py3-none-any.whl", using: :nounzip
      sha256 "ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2"
    end
    resource "setuptools-scm" do
      url "https://files.pythonhosted.org/packages/da/f5/54538a1f17ea753c42b0928dc2e62986d463f8c393340b9a1e602f2d4dd9/setuptools_scm-10.3.4-py3-none-any.whl", using: :nounzip
      sha256 "82f34c3e3084fc2b57d397200637cc13f2338004052d2fee47baa5f0e902464e"
    end
    resource "six" do
      url "https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl", using: :nounzip
      sha256 "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274"
    end
    resource "sniffio" do
      url "https://files.pythonhosted.org/packages/e9/44/75a9c9421471a6c4805dbf2356f7c181a29c1879239abab1ea2cc8f38b40/sniffio-1.3.1-py3-none-any.whl", using: :nounzip
      sha256 "2f6da418d1f1e0fddd844478f41680e794e6051915791a034ff65e5f100525a2"
    end
    resource "starlette" do
      url "https://files.pythonhosted.org/packages/f3/93/181df62699d9b5aca1d87e5cfda131dac87e3cdaebf668662f7206ca3470/starlette-1.9.0-py3-none-any.whl", using: :nounzip
      sha256 "fd3f159936e882d06c1108f84688f7cda2cf85fc6a592a50edbd175e882c2ddc"
    end
    resource "tabulate" do
      url "https://files.pythonhosted.org/packages/99/55/db07de81b5c630da5cbf5c7df646580ca26dfaefa593667fc6f2fe016d2e/tabulate-0.10.0-py3-none-any.whl", using: :nounzip
      sha256 "f0b0622e567335c8fabaaa659f1b33bcb6ddfe2e496071b743aa113f8774f2d3"
    end
    resource "textual" do
      url "https://files.pythonhosted.org/packages/fb/be/35261223d9416a0751cdff1c7b4a6f881387218a12d439fe22fefebc8c04/textual-8.2.8-py3-none-any.whl", using: :nounzip
      sha256 "267375fd402dc8d981457212efa71f0e3365fd17bba144ba9bb3ed7563cb374a"
    end
    resource "tiktoken" do
      url "https://files.pythonhosted.org/packages/69/9f/fe6b1aca23331aa5271df5a4bd07bf68a7059254d47faee1b8272592a777/tiktoken-0.14.0-cp312-cp312-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "d6cebe67765569df3dafac8474e4eccf5c19d24140492567a5e58a11445732a4"
    end
    resource "tokenizers" do
      url "https://files.pythonhosted.org/packages/b2/72/01e49f032bb346e5aaf06c10c74fe8aeec847173adbadd66eb7c53054bf2/tokenizers-0.23.3-cp310-abi3-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "68649e97d5b43c44c031d8d848874a6eecae8f8fe40ea989aa777a5a83aca716"
    end
    resource "tomlkit" do
      url "https://files.pythonhosted.org/packages/da/46/7d84138a60a8bd796825b2d38ebe92d0d16501ca57d501b7c5d677401bbc/tomlkit-0.15.2-py3-none-any.whl", using: :nounzip
      sha256 "05562412163a3037b94497385fb7f9204c637bc605af7a48199e41cf2272f437"
    end
    resource "tqdm" do
      url "https://files.pythonhosted.org/packages/a7/03/921a3d3c75785aca9ebfbfcabfbc3a1be12e2ab5265deb026d55a5a3f83e/tqdm-4.70.1-py3-none-any.whl", using: :nounzip
      sha256 "c293e525e6fef9c20e8728fd4612df02a0aa31bb5fe91ecd93e123b1b7bffa73"
    end
    resource "trove-classifiers" do
      url "https://files.pythonhosted.org/packages/30/81/0da8afb52a71d0a4f2bd3152357b1a441e393b286374802b9d3addab4ab5/trove_classifiers-2026.9.21.13-py3-none-any.whl", using: :nounzip
      sha256 "8b1ff4f9c191b1040b71c37f1e445ab99732911e3cd91de52838453a854d7a17"
    end
    resource "typing-extensions" do
      url "https://files.pythonhosted.org/packages/49/d3/b8441a820a491ddfc024b0b0cf0393375b75ea13866d9c66727e54c2fc80/typing_extensions-4.16.0-py3-none-any.whl", using: :nounzip
      sha256 "481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8"
    end
    resource "typing-inspection" do
      url "https://files.pythonhosted.org/packages/67/81/4add07e5172b7ac40d8ed5ff580409a7801a4fe26d529bdd915401dabfbe/typing_inspection-0.4.4-py3-none-any.whl", using: :nounzip
      sha256 "65b8397ba37ccbce054456aaccddfc91e6e3083c92824df348d96ca832f3f147"
    end
    resource "urllib3" do
      url "https://files.pythonhosted.org/packages/92/9d/c4e665119135114480843e7ab388fa94d8480650450e6f8e26b70d323a4c/urllib3-2.8.0-py3-none-any.whl", using: :nounzip
      sha256 "0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3"
    end
    resource "uvicorn" do
      url "https://files.pythonhosted.org/packages/38/0c/b54a4fdd7f90a3af8b02ebc9ce6712c2c208b7926a2f7bad95c33ebbe943/uvicorn-0.54.0-py3-none-any.whl", using: :nounzip
      sha256 "505bdb0f318731d45f1f712071fc781a8981f6847a31c902c9f5e652d4f67faf"
    end
    resource "uvloop" do
      url "https://files.pythonhosted.org/packages/05/98/04e766a6de99e6f7f955ecb7829e8d5a557de3427cb85be2236de54dda0c/uvloop-0.23.0-cp312-cp312-macosx_10_13_universal2.whl", using: :nounzip
      sha256 "93935ab27b6eaef4c3e5489aebc84284f0644592f7ab516df60ee1b27eaf5eb3"
    end
    resource "vcs-versioning" do
      url "https://files.pythonhosted.org/packages/73/1d/ad4064bf12f4503bf61e65d74c93c523672776d25ee0a06aaf42ae09ef3f/vcs_versioning-2.6.0-py3-none-any.whl", using: :nounzip
      sha256 "f8bebd1302ebc12e67ceb30fc7dd698ec969414b6fa43b30c3f14ac9b1e72c41"
    end
    resource "watchfiles" do
      url "https://files.pythonhosted.org/packages/c7/8a/894799b485fe9473ad10422a0d9668e53fb78e3a2b5cc6061159572844ad/watchfiles-1.3.0-cp310-abi3-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "bbc1198edfdc90fda0600f825aa94150f428dfcbf8138746f55998e0e660d64c"
    end
    resource "websockets" do
      url "https://files.pythonhosted.org/packages/d7/b0/3f01fcb3406662f6deb1e3e72b34dd0979e993991c0b7435a9e12bc14f02/websockets-17.3-py3-none-any.whl", using: :nounzip
      sha256 "dc2b495a92b3971966bf102e73589f950db3ec1ca6713265355ce7771d97b199"
    end
    resource "yara-x" do
      url "https://files.pythonhosted.org/packages/0f/bb/22b5cb8b57d60a258196ff46392be59f9261c7dd33a237960059de5c9d55/yara_x-1.22.0-cp39-abi3-macosx_14_0_arm64.whl", using: :nounzip
      sha256 "eb6d4812e73614643f3c10a2592692b544ca7db43eacb2c8c649a1c9658382c3"
    end
    resource "yarl" do
      url "https://files.pythonhosted.org/packages/54/22/318c7980066769c6bcd9221ed2248294f5698811da099013098c670565ed/yarl-1.25.1-py3-none-any.whl", using: :nounzip
      sha256 "681c758b0490f9e96b78e5fa8e8dc6e648e9185bb6eaebe73183c33ea0c445f3"
    end
    resource "zipp" do
      url "https://files.pythonhosted.org/packages/b5/98/df615823cd9419131ce19fba00de53a663794369e198aade064a244b385d/zipp-4.1.1-py3-none-any.whl", using: :nounzip
      sha256 "8979f52d874162f485ff2981e3891f3a3317b7a3dd43ff1e1775b9304f307a9c"
    end
  end
  on_intel do
    resource "cel-helper" do
      url "https://files.pythonhosted.org/packages/ce/28/f49415469823bff3651fe5f4b93b43fa1d8ae21f5cf730ae2de804967d20/cisco_ai_skill_scanner-2.3.1-cp311.cp312.cp313.cp314-none-macosx_13_0_x86_64.whl"
      sha256 "513648df459f0c05ba7bd7eb9dce51329aaf9d979a98acd5503521d43243fc2d"
    end
    resource "aiohappyeyeballs" do
      url "https://files.pythonhosted.org/packages/71/43/1947f06babed6b3f1d7f38b0c767f52df66bfb2bc10b468c4a7de9eceff2/aiohappyeyeballs-2.7.1-py3-none-any.whl", using: :nounzip
      sha256 "9243213661e29250eb41368e5daa826fc017156c3b8a11440826b2e3ed376472"
    end
    resource "aiohttp" do
      url "https://files.pythonhosted.org/packages/68/30/173960c42b05a6c59f7558e4b12a4b0d9ba376cf6aa9bde7f9e08a30ca8d/aiohttp-3.14.5-py3-none-any.whl", using: :nounzip
      sha256 "efc21a454892828368b11c2c780de0ff8bc991f73f6b99c6b66e56205470929b"
    end
    resource "aiosignal" do
      url "https://files.pythonhosted.org/packages/fb/76/641ae371508676492379f16e2fa48f4e2c11741bd63c48be4b12a6b09cba/aiosignal-1.4.0-py3-none-any.whl", using: :nounzip
      sha256 "053243f8b92b990551949e63930a839ff0cf0b0ebbe0597b0f3fb19e1a0fe82e"
    end
    resource "annotated-doc" do
      url "https://files.pythonhosted.org/packages/3e/30/e900b21425a860e195f32e37657aa1f7c7f2b1bfb26f03ca209b90933c06/annotated_doc-0.0.5-py3-none-any.whl", using: :nounzip
      sha256 "117bac03a25ede5df5440e855b32d556049ca169ead221505badf432fed4b101"
    end
    resource "annotated-types" do
      url "https://files.pythonhosted.org/packages/99/91/8acff4f5e50511b911bbccb72b8628a49c68ce14148cd9f6431094859a90/annotated_types-0.8.0-py3-none-any.whl", using: :nounzip
      sha256 "f072f4d804ea359e4eaf198b1af7a8b0943881a87f31bb764f8bf219bb9419e0"
    end
    resource "anthropic" do
      url "https://files.pythonhosted.org/packages/2f/1a/b1bd30cda3790557e8791bec5922a6ec8fabb6fa8b008c76a39cf7be6152/anthropic-0.125.0-py3-none-any.whl", using: :nounzip
      sha256 "3486013602eca76d8b12540764e53654f02cf4951110bca86cf06e67428a9f21"
    end
    resource "anyio" do
      url "https://files.pythonhosted.org/packages/12/b8/4bd346e22b28902df4d651910f5242c28d84e4a5c2435ca5c3f797ed7e2e/anyio-4.15.1-py3-none-any.whl", using: :nounzip
      sha256 "6152fdbbf9a77fdec97731721bebf7c4c44f7c29b424b0065826173efc7ed101"
    end
    resource "attrs" do
      url "https://files.pythonhosted.org/packages/64/b4/17d4b0b2a2dc85a6df63d1157e028ed19f90d4cd97c36717afef2bc2f395/attrs-26.1.0-py3-none-any.whl", using: :nounzip
      sha256 "c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309"
    end
    resource "boto3" do
      url "https://files.pythonhosted.org/packages/78/de/cf71466f55516e61d8048374776b390a036a1b48c9a7a4cd8e21f8b27980/boto3-1.43.116-py3-none-any.whl", using: :nounzip
      sha256 "9dca4dbd464b189041b27b5a02280bd5e02c3051bebf6bd03cd0e47aaf558030"
    end
    resource "botocore" do
      url "https://files.pythonhosted.org/packages/3e/2e/449851ffdd5c6cd521d309bba501077025929ba0ef005a3052f43fca509e/botocore-1.43.116-py3-none-any.whl", using: :nounzip
      sha256 "92f1efe8434183f08f91a61478925f5f8d23082024556f269f916477040e26f4"
    end
    resource "certifi" do
      url "https://files.pythonhosted.org/packages/c4/51/29046e48f693c54e5b7412216d447a1d8362c9653148d98c02cdf65fa733/certifi-2026.10.19-py3-none-any.whl", using: :nounzip
      sha256 "42d35340cc5b9ba78e818ddbff0c5b1c2b779de448a340fd1b989f5fa8670e1b"
    end
    resource "cffi" do
      url "https://files.pythonhosted.org/packages/10/69/43965eccfdead3b9220015fd1320e117be8c6ed01a62ffab76eeb752f5d5/cffi-2.1.1-cp312-cp312-macosx_10_15_x86_64.whl", using: :nounzip
      sha256 "c8c69575568085ba0b1b10c0249d779a214aea6f6522e949a0fc9fb0fcb449d0"
    end
    resource "charset-normalizer" do
      url "https://files.pythonhosted.org/packages/fc/ad/d07d7862a62ffa6d79d68074d14823243dd235a77c45262acbf6adeb28bf/charset_normalizer-3.5.2-py3-none-any.whl", using: :nounzip
      sha256 "b6b751274acb69d77b3323d6b7dbaa3c7fdfc1eb829b7eb61d262f32e1af9685"
    end
    resource "click" do
      url "https://files.pythonhosted.org/packages/58/50/6c0d534c5f134586a8e1ba4e330569e32f057e33372ae556463212fb4cd3/click-8.5.0-py3-none-any.whl", using: :nounzip
      sha256 "255bc9599cf7748b4b1a446ccc735421bd08a2ae529a8b88597d3de5664ee360"
    end
    resource "colorclass" do
      url "https://files.pythonhosted.org/packages/30/b6/daf3e2976932da4ed3579cff7a30a53d22ea9323ee4f0d8e43be60454897/colorclass-2.2.2-py2.py3-none-any.whl", using: :nounzip
      sha256 "6f10c273a0ef7a1150b1120b6095cbdd68e5cf36dfd5d0fc957a2500bbf99a55"
    end
    resource "coloredlogs" do
      url "https://files.pythonhosted.org/packages/a7/06/3d6badcf13db419e25b07041d9c7b4a2c331d3f4e7134445ec5df57714cd/coloredlogs-15.0.1-py2.py3-none-any.whl", using: :nounzip
      sha256 "612ee75c546f53e92e70049c9dbfcc18c935a2b9a53b66085ce9ef6a6e5c0934"
    end
    resource "confusable-homoglyphs" do
      url "https://files.pythonhosted.org/packages/c5/6e/c0fcbb7d341a46cf4241a6aa9e6a737734f0657521fc1bcd074953fe4eea/confusable_homoglyphs-3.3.1-py2.py3-none-any.whl", using: :nounzip
      sha256 "84c92cb79dc7f55aa290d0762b2349abd8dee4c16fbe6f99eac978d394e2e6a1"
    end
    resource "cryptography" do
      url "https://files.pythonhosted.org/packages/1b/bc/ee4137cbbe105652c0ee4252792b78fc8e7afa4b8e61d9d5dc05a7f45731/cryptography-48.0.1-cp311-abi3-macosx_10_9_universal2.whl", using: :nounzip
      sha256 "3e4a1a3232eef2e6c732827d5722db29a0cc8b27af2a4d865b094cf954be9ca1"
    end
    resource "distro" do
      url "https://files.pythonhosted.org/packages/12/b3/231ffd4ab1fc9d679809f356cebee130ac7daa00d6d6f3206dd4fd137e9e/distro-1.9.0-py3-none-any.whl", using: :nounzip
      sha256 "7bffd925d65168f85027d8da9af6bddab658135b840670a223589bc0c8ef02b2"
    end
    resource "docstring-parser" do
      url "https://files.pythonhosted.org/packages/a7/5f/ed01f9a3cdffbd5a008556fc7b2a08ddb1cc6ace7effa7340604b1d16699/docstring_parser-0.18.0-py3-none-any.whl", using: :nounzip
      sha256 "b3fcbed555c47d8479be0796ef7e19c2670d428d72e96da63f3a40122860374b"
    end
    resource "easygui" do
      url "https://files.pythonhosted.org/packages/8e/a7/b276ff776533b423710a285c8168b52551cb2ab0855443131fdc7fd8c16f/easygui-0.98.3-py2.py3-none-any.whl", using: :nounzip
      sha256 "33498710c68b5376b459cd3fc48d1d1f33822139eb3ed01defbc0528326da3ba"
    end
    resource "fastapi" do
      url "https://files.pythonhosted.org/packages/50/c3/759716158338892ed8e483077241cdf80e1fd727f56baf750c75bfea58de/fastapi-0.157.0-py3-none-any.whl", using: :nounzip
      sha256 "45b5cbf098ce3f47e008ca67931ce333d028129c823e3b6766a3bd0d70b81f7f"
    end
    resource "fastuuid" do
      url "https://files.pythonhosted.org/packages/02/a2/e78fcc5df65467f0d207661b7ef86c5b7ac62eea337c0c0fcedbeee6fb13/fastuuid-0.14.0-cp312-cp312-macosx_10_12_x86_64.macosx_11_0_arm64.macosx_10_12_universal2.whl", using: :nounzip
      sha256 "77e94728324b63660ebf8adb27055e92d2e4611645bf12ed9d88d30486471d0a"
    end
    resource "filelock" do
      url "https://files.pythonhosted.org/packages/15/df/31098c5aeb4d966b553641472bd55fcf5fdfac953549894b8a765ba44e91/filelock-3.32.7-py3-none-any.whl", using: :nounzip
      sha256 "65ff0d0190ea42038b32bda4b77834fb05be2cad4c5b9b01aa4dfb3614536e52"
    end
    resource "flatbuffers" do
      url "https://files.pythonhosted.org/packages/e8/2d/d2a548598be01649e2d46231d151a6c56d10b964d94043a335ae56ea2d92/flatbuffers-25.12.19-py2.py3-none-any.whl", using: :nounzip
      sha256 "7634f50c427838bb021c2d66a3d1168e9d199b0607e6329399f04846d42e20b4"
    end
    resource "frozenlist" do
      url "https://files.pythonhosted.org/packages/9a/9a/e35b4a917281c0b8419d4207f4334c8e8c5dbf4f3f5f9ada73958d937dcc/frozenlist-1.8.0-py3-none-any.whl", using: :nounzip
      sha256 "0c18a16eab41e82c295618a77502e17b195883241c563b00f0aa5106fc4eaa0d"
    end
    resource "fsspec" do
      url "https://files.pythonhosted.org/packages/6c/c0/a98505f18594f1bce828bb159cec0fcf9860562f1a2c85913409fc8f3d9e/fsspec-2026.9.0-py3-none-any.whl", using: :nounzip
      sha256 "8dd6e646e99ea382bd85f97a45e6b526a442d79423a7dc673f1e2756d05fcb5f"
    end
    resource "h11" do
      url "https://files.pythonhosted.org/packages/04/4b/29cac41a4d98d144bf5f6d33995617b185d14b22401f75ca86f384e87ff1/h11-0.16.0-py3-none-any.whl", using: :nounzip
      sha256 "63cf8bbe7522de3bf65932fda1d9c2772064ffb3dae62d55932da54b31cb6c86"
    end
    resource "h2" do
      url "https://files.pythonhosted.org/packages/7e/22/e85faf23bd72a92d1921e37d674ca56eb298a3c8be31fdecef0ff2b3aaac/h2-4.4.1-py3-none-any.whl", using: :nounzip
      sha256 "0e25f1462b23c9cb82d9eb02e28bc706dac2a68cb457c6a0d74d63c8a2a5d0e6"
    end
    resource "hatch-vcs" do
      url "https://files.pythonhosted.org/packages/5f/48/1f85cee4b7b4f40b9b814b1febbc661bda6ced9649e410a0b74f6e415dd0/hatch_vcs-0.5.0-py3-none-any.whl", using: :nounzip
      sha256 "b49677dbdc597460cc22d01b27ab3696f5e16a21ecf2700fb01bc28e1f2a04a7"
    end
    resource "hatchling" do
      url "https://files.pythonhosted.org/packages/5f/80/91f51f439c05d4ec4623c22928ce16a938d6d793bf709477830823497859/hatchling-1.32.4-py3-none-any.whl", using: :nounzip
      sha256 "08ecf7548fb48205e7f213d70c71e67b8271b7242093dc3f1da578b42c734a2c"
    end
    resource "hf-xet" do
      url "https://files.pythonhosted.org/packages/9c/0b/b03be21ffaada749ba0d3197d8aefbf1aa698bac149580421c15239b299e/hf_xet-1.7.0-cp38-abi3-macosx_10_12_x86_64.whl", using: :nounzip
      sha256 "e3e88a7a75d7d95cbee1f37dc31341d6201124cf21c6c4b1dfab8ccba9b09e0f"
    end
    resource "hpack" do
      url "https://files.pythonhosted.org/packages/71/b4/4a9fcfb2aef6ba44d9073ecd301443aa00b3dac95de5619f2a7de7ec8a91/hpack-4.2.0-py3-none-any.whl", using: :nounzip
      sha256 "858ac0b02280fa582b5080d68db0899c62a80375e0e5413a74970c5e518b6986"
    end
    resource "httpcore" do
      url "https://files.pythonhosted.org/packages/7e/f5/f66802a942d491edb555dd61e3a9961140fd64c90bce1eafd741609d334d/httpcore-1.0.9-py3-none-any.whl", using: :nounzip
      sha256 "2d400746a40668fc9dec9810239072b40b4484b640a8c38fd654a024c7a1bf55"
    end
    resource "httptools" do
      url "https://files.pythonhosted.org/packages/c2/0b/9b6de4a01a563a904d0826c9069c824b330e1816df26c9bdf93f60b50857/httptools-0.9.0-cp312-cp312-macosx_11_0_x86_64.whl", using: :nounzip
      sha256 "45b3002392948dcf578029c89f6318e1289a993a1a5ec38a4161560fab60f811"
    end
    resource "httpx" do
      url "https://files.pythonhosted.org/packages/2a/39/e50c7c3a983047577ee07d2a9e53faf5a69493943ec3f6a384bdc792deb2/httpx-0.28.1-py3-none-any.whl", using: :nounzip
      sha256 "d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad"
    end
    resource "huggingface-hub" do
      url "https://files.pythonhosted.org/packages/fc/16/963096d224b80909432dc16561a615fd33d2d13beef3ce4c63fa25e40867/huggingface_hub-1.33.0-py3-none-any.whl", using: :nounzip
      sha256 "04e434b06e100eddbce9a6e817d72693a7884b10a79bd67ab48080d5c07eb899"
    end
    resource "humanfriendly" do
      url "https://files.pythonhosted.org/packages/f0/0f/310fb31e39e2d734ccaa2c0fb981ee41f7bd5056ce9bc29b2248bd569169/humanfriendly-10.0-py2.py3-none-any.whl", using: :nounzip
      sha256 "1697e1a8a8f550fd43c2865cd84542fc175a61dcb779b6fee18cf6b6ccba1477"
    end
    resource "hyperframe" do
      url "https://files.pythonhosted.org/packages/48/30/47d0bf6072f7252e6521f3447ccfa40b421b6824517f82854703d0f5a98b/hyperframe-6.1.0-py3-none-any.whl", using: :nounzip
      sha256 "b03380493a519fce58ea5af42e4a42317bf9bd425596f7a0835ffce80f1a42e5"
    end
    resource "idna" do
      url "https://files.pythonhosted.org/packages/58/a2/bb081bab032533a855d44de1d56f8e8426114ff1ba5d1f07a438a0a654f8/idna-3.20-py3-none-any.whl", using: :nounzip
      sha256 "ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c"
    end
    resource "importlib-metadata" do
      url "https://files.pythonhosted.org/packages/7d/f9/97f2ca8bb3ec6e4b1d64f983ebe98b9a192faddff67fac3d6303a537e670/importlib_metadata-8.9.0-py3-none-any.whl", using: :nounzip
      sha256 "e0f761b6ea91ced3b0844c14c9d955224d538105921f8e6754c00f6ca79fba7f"
    end
    resource "Jinja2" do
      url "https://files.pythonhosted.org/packages/62/a1/3d680cbfd5f4b8f15abc1d571870c5fc3e594bb582bc3b64ea099db13e56/jinja2-3.1.6-py3-none-any.whl", using: :nounzip
      sha256 "85ece4451f492d0c13c5dd7c13a64681a86afae63a5f347908daf103ce6d2f67"
    end
    resource "jiter" do
      url "https://files.pythonhosted.org/packages/aa/f8/07bd8c3a23f7a8a6875e6a820bbffe1483a18f18f9398a91b5495123176e/jiter-0.17.0-cp312-cp312-macosx_10_12_x86_64.whl", using: :nounzip
      sha256 "ebf918dfd6a74adc1b9ad71f63c4ab00902fcd3b7fd39f2e24d871db8d713b91"
    end
    resource "jmespath" do
      url "https://files.pythonhosted.org/packages/14/2f/967ba146e6d58cf6a652da73885f52fc68001525b4197effc174321d70b4/jmespath-1.1.0-py3-none-any.whl", using: :nounzip
      sha256 "a5663118de4908c91729bea0acadca56526eb2698e83de10cd116ae0f4e97c64"
    end
    resource "jsonschema" do
      url "https://files.pythonhosted.org/packages/69/90/f63fb5873511e014207a475e2bb4e8b2e570d655b00ac19a9a0ca0a385ee/jsonschema-4.26.0-py3-none-any.whl", using: :nounzip
      sha256 "d489f15263b8d200f8387e64b4c3a75f06629559fb73deb8fdfb525f2dab50ce"
    end
    resource "jsonschema-specifications" do
      url "https://files.pythonhosted.org/packages/41/45/1a4ed80516f02155c51f51e8cedb3c1902296743db0bbc66608a0db2814f/jsonschema_specifications-2025.9.1-py3-none-any.whl", using: :nounzip
      sha256 "98802fee3a11ee76ecaca44429fda8a41bff98b00a0f2838151b113f210cc6fe"
    end
    resource "linkify-it-py" do
      url "https://files.pythonhosted.org/packages/13/d4/1152d1c7ab42d8b908be64fd200ddc870dc9d4925e951198702084aa1a7d/linkify_it_py-2.2.0-py3-none-any.whl", using: :nounzip
      sha256 "3adc40eb5af300b2605fcfdb968c24e1d780a90f1f2221af7c15e5111e94d443"
    end
    resource "litellm" do
      url "https://files.pythonhosted.org/packages/0f/47/1038af80d9831972fae8712a890c30252f51c514c092d83e0f1330bb1fa1/litellm-1.106.2-cp310-abi3-macosx_10_12_x86_64.whl", using: :nounzip
      sha256 "bf6f13445bb59d8d02131bbc1fb57161d1ae629bec65dc66f9add4c09fb6994a"
    end
    resource "magika" do
      url "https://files.pythonhosted.org/packages/93/eb/24d94db0530029649b266ec3ca8221c07f2754f56046181f13237d2518f5/magika-1.0.3-py3-none-any.whl", using: :nounzip
      sha256 "938d8e033953f2ddeb8c35dc423aa289ca116bfa7a71a778f6e77460f9025803"
    end
    resource "markdown-it-py" do
      url "https://files.pythonhosted.org/packages/b3/81/4da04ced5a082363ecfa159c010d200ecbd959ae410c10c0264a38cac0f5/markdown_it_py-4.2.0-py3-none-any.whl", using: :nounzip
      sha256 "9f7ebbcd14fe59494226453aed97c1070d83f8d24b6fc3a3bcf9a38092641c4a"
    end
    resource "MarkupSafe" do
      url "https://files.pythonhosted.org/packages/81/09/4c59d56b8461ae8eb0d8ba34bb25b7e618547044679d58a82ef9b2479fc1/markupsafe-3.0.4-cp312-cp312-macosx_10_13_x86_64.whl", using: :nounzip
      sha256 "61631e08084be9e21a8967ec3139c7616ed7c5e9368e05c86d1b39562c8a57b6"
    end
    resource "mdit-py-plugins" do
      url "https://files.pythonhosted.org/packages/a5/69/6da5581c6a7fede7dc261bf4e67d6adca4196f176b43288b55b3db395b6e/mdit_py_plugins-0.6.1-py3-none-any.whl", using: :nounzip
      sha256 "214c82fb2ac524472ab6a5bcab1de80f73b50443e187f401bfd77efbc7c6481d"
    end
    resource "mdurl" do
      url "https://files.pythonhosted.org/packages/b3/38/89ba8ad64ae25be8de66a6d463314cf1eb366222074cfda9ee839c56a4b4/mdurl-0.1.2-py3-none-any.whl", using: :nounzip
      sha256 "84008a41e51615a49fc9966191ff91509e3c40b939176e643fd50a5c2196b8f8"
    end
    resource "mpmath" do
      url "https://files.pythonhosted.org/packages/43/e3/7d92a15f894aa0c9c4b49b8ee9ac9850d6e63b03c9c32c0367a13ae62209/mpmath-1.3.0-py3-none-any.whl", using: :nounzip
      sha256 "a0b2b9fe80bbcd81a6647ff13108738cfb482d481d826cc0e02f5b35e5c88d2c"
    end
    resource "msoffcrypto-tool" do
      url "https://files.pythonhosted.org/packages/3c/85/9e359fa9279e1d6861faaf9b6f037a3226374deb20a054c3937be6992013/msoffcrypto_tool-6.0.0-py3-none-any.whl", using: :nounzip
      sha256 "46c394ed5d9641e802fc79bf3fb0666a53748b23fa8c4aa634ae9d30d46fe397"
    end
    resource "multidict" do
      url "https://files.pythonhosted.org/packages/d0/86/a3de309c5e28ee85b314d0e3ba0e0dea6fd361c313322a05e67be4656e1e/multidict-7.1.0-py3-none-any.whl", using: :nounzip
      sha256 "d9ef29cfd98e17085b4f91bba8fa1570bec6787d5c52ce653ed33a58785585d0"
    end
    resource "numpy" do
      url "https://files.pythonhosted.org/packages/d0/97/ba2074e92b7befea137e77ea8471e768bbd87c339b7e8c9f5a931949f977/numpy-2.5.4-cp312-cp312-macosx_10_13_x86_64.whl", using: :nounzip
      sha256 "c6342f54c67093cae5c0227eb0eb772fdb79f2a2c37a6eb278b9909ee06aa356"
    end
    resource "olefile" do
      url "https://files.pythonhosted.org/packages/17/d3/b64c356a907242d719fc668b71befd73324e47ab46c8ebbbede252c154b2/olefile-0.47-py2.py3-none-any.whl", using: :nounzip
      sha256 "543c7da2a7adadf21214938bb79c83ea12b473a4b6ee4ad4bf854e7715e13d1f"
    end
    resource "oletools" do
      url "https://files.pythonhosted.org/packages/ac/ff/05257b7183279b80ecec6333744de23f48f0faeeba46c93e6d13ce835515/oletools-0.60.2-py2.py3-none-any.whl", using: :nounzip
      sha256 "72ad8bd748fd0c4e7b5b4733af770d11543ebb2bf2697455f99f975fcd50cc96"
    end
    resource "onnxruntime" do
      url "https://files.pythonhosted.org/packages/91/9d/a81aafd899b900101988ead7fb14974c8a58695338ab6a0f3d6b0100f30b/onnxruntime-1.23.2-cp312-cp312-macosx_13_0_x86_64.whl", using: :nounzip
      sha256 "218295a8acae83905f6f1aed8cacb8e3eb3bd7513a13fe4ba3b2664a19fc4a6b"
    end
    resource "openai" do
      url "https://files.pythonhosted.org/packages/64/a8/bb76c7356de8ad57f59d5ff993d434df0607f07f08bcc9c9a5c275e399c0/openai-2.54.0-py3-none-any.whl", using: :nounzip
      sha256 "89089789197ccdb87f173a03145ed1598d00795220c93e96cf712b1cbf5e5f2b"
    end
    resource "opentelemetry-api" do
      url "https://files.pythonhosted.org/packages/1e/41/f7dcf80b81ee8e71c1a2b59f14208bc723edbd89ed027a73b175abf6348e/opentelemetry_api-1.45.1-py3-none-any.whl", using: :nounzip
      sha256 "b31553efa588ae44bc306f863c785c5333a9ecc091248c6ee68b4b6c87fdedfb"
    end
    resource "packaging" do
      url "https://files.pythonhosted.org/packages/63/34/ba1c580383c9eada3711951fef0795c80b829a078d72188184bcab9dd527/packaging-26.3-py3-none-any.whl", using: :nounzip
      sha256 "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c"
    end
    resource "pathspec" do
      url "https://files.pythonhosted.org/packages/f1/d9/7fb5aa316bc299258e68c73ba3bddbc499654a07f151cba08f6153988714/pathspec-1.1.1-py3-none-any.whl", using: :nounzip
      sha256 "a00ce642f577bf7f473932318056212bc4f8bfdf53128c78bbd5af0b9b20b189"
    end
    resource "pcodedmp" do
      url "https://files.pythonhosted.org/packages/ba/72/b380fb5c89d89c3afafac8cf02a71a45f4f4a4f35531ca949a34683962d1/pcodedmp-1.2.6-py2.py3-none-any.whl", using: :nounzip
      sha256 "4441f7c0ab4cbda27bd4668db3b14f36261d86e5059ce06c0828602cbe1c4278"
    end
    resource "pdfid" do
      url "https://files.pythonhosted.org/packages/29/48/9ba402d773ffac76515720f98f3a01a2802737b6a2b75cac1fb8ba269a7a/pdfid-1.1.3-py3-none-any.whl", using: :nounzip
      sha256 "9b9b72145a81759c6e9f327eb0e115a30a3fbd140fa5bd5da0d1956ec4c9f65a"
    end
    resource "platformdirs" do
      url "https://files.pythonhosted.org/packages/6c/8a/1d8cb3842909dc193a73835adedf412e32e18f8ffd59f43983949622fe6f/platformdirs-4.13.5-py3-none-any.whl", using: :nounzip
      sha256 "53d3ec4280b815c1e0b02edad7f9ee8fda1ba9c0865dd9c2e6e63849ce82fc1e"
    end
    resource "pluggy" do
      url "https://files.pythonhosted.org/packages/40/9e/2b38731e0fc536806f16490e1a12d7f0dc2a1235aa8cc07bcc75416a7daa/pluggy-1.7.0-py3-none-any.whl", using: :nounzip
      sha256 "7dd7b0d8832ba3cb632c306926ded123429211b83641b35dc5c41ad2d34f9bec"
    end
    resource "propcache" do
      url "https://files.pythonhosted.org/packages/f5/cd/785c64ed382f3f04201870267b02783f63b4678c2acfddc177a3ebcc2727/propcache-0.5.4-py3-none-any.whl", using: :nounzip
      sha256 "62c60aec739ed00124573cce1178138fd690c7676352d67a37328c1cf51d7468"
    end
    resource "protobuf" do
      url "https://files.pythonhosted.org/packages/c4/72/02445137af02769918a93807b2b7890047c32bfb9f90371cbc12688819eb/protobuf-6.33.6-py3-none-any.whl", using: :nounzip
      sha256 "77179e006c476e69bf8e8ce866640091ec42e1beb80b213c3900006ecfba6901"
    end
    resource "pycparser" do
      url "https://files.pythonhosted.org/packages/90/11/0e6f11117525ff0eec40ebac3d313376f102df93ca44ad9e893ee85e4f89/pycparser-3.11-py3-none-any.whl", using: :nounzip
      sha256 "51d5a8ba2be0bbe440b99d2112604c95bbbc3c2748a64260186c541e1729cd80"
    end
    resource "pydantic" do
      url "https://files.pythonhosted.org/packages/35/ea/a56b9fe5066f3537b7882f77e9c5dfb26d8c2eefdaed9b5fc73d57b4dc22/pydantic-2.14.1-py3-none-any.whl", using: :nounzip
      sha256 "9195d967ec791692a04438115466764fb8b9a27b31f14a760437694f40d6b454"
    end
    resource "pydantic_core" do
      url "https://files.pythonhosted.org/packages/ee/94/101b49a6c63f99586755690696eae14532772587d9e39e93f7b8d28a49da/pydantic_core-2.50.1-cp312-cp312-macosx_10_12_x86_64.whl", using: :nounzip
      sha256 "704075d10b74f2f3c6e15407c696d88701df35fc8953f434a431add0d0074db0"
    end
    resource "pydantic-settings" do
      url "https://files.pythonhosted.org/packages/3c/74/fdf926afe145d8629c4b2ff57f4ea1d64ed7abc4d84d97463b2517a2547e/pydantic_settings-2.16.1-py3-none-any.whl", using: :nounzip
      sha256 "30f5313340da4e8f1b440d1910b92a5bc3ccbb6b4ba70ec2b8395bc921f418f5"
    end
    resource "Pygments" do
      url "https://files.pythonhosted.org/packages/71/46/17f022dd3e953bf20a04a028a21ec746d942f8d2af30fa0f124fa0e6a684/pygments-2.21.0-py3-none-any.whl", using: :nounzip
      sha256 "2363c69b61c4a97c838da3b130dcd6468f4848992b21a82f2a63ec34377137d9"
    end
    resource "PyJWT" do
      url "https://files.pythonhosted.org/packages/50/ca/44de4e75f8aadc457f0634be3b542815078ded46dca30efb960edeecad6e/pyjwt-2.15.1-py3-none-any.whl", using: :nounzip
      sha256 "42d59d631f7768a1028a64c7ff581a9bf7519804daf91fc5b6c56e30eec5e193"
    end
    resource "pyparsing" do
      url "https://files.pythonhosted.org/packages/38/bb/d215ee7c73b61497b28a5503f9f53523f294fcc936762b7caf90e0c1c2b5/pyparsing-3.3.3-py3-none-any.whl", using: :nounzip
      sha256 "ece8c00a69cf01b45d0b1dedabb469c90d8caf996d4fda40f147627a122849a4"
    end
    resource "python-dateutil" do
      url "https://files.pythonhosted.org/packages/ec/57/56b9bcc3c9c6a792fcbaf139543cee77261f3651ca9da0c93f5c1221264b/python_dateutil-2.9.0.post0-py2.py3-none-any.whl", using: :nounzip
      sha256 "a8b2bc7bffae282281c8140a97d3aa9c14da0b136dfe83f850eea9a5f7470427"
    end
    resource "python-dotenv" do
      url "https://files.pythonhosted.org/packages/60/d1/38f3a3405989a89ac18390803e70c6ad7c7760da4f9b83cbeca0c44a0c72/python_dotenv-1.2.4-py3-none-any.whl", using: :nounzip
      sha256 "42269a8a5b3fd54ffa6f3d84b18abed50064717576b4ecf03dc4a55d8aa04fdc"
    end
    resource "python-frontmatter" do
      url "https://files.pythonhosted.org/packages/a6/a3/17c284b4f4d8ad50f0f9ba70ad8fcc35c777aeafcdbbffdd91bbdc5ab379/python_frontmatter-1.3.0-py3-none-any.whl", using: :nounzip
      sha256 "9f7dd9260bec99044219159a329f64f039087f9d1a2124c9442556f2fe6f82ec"
    end
    resource "python-multipart" do
      url "https://files.pythonhosted.org/packages/e1/04/e8135ebd1ad02c56ec633277529b2602ff99ff634be76cdba5744cf554fd/python_multipart-0.0.32-py3-none-any.whl", using: :nounzip
      sha256 "ff6d3f776f16878c894e52e107296ffc890e913c611b1a4ec6c44e2821fe2e23"
    end
    resource "PyYAML" do
      url "https://files.pythonhosted.org/packages/d1/33/422b98d2195232ca1826284a76852ad5a86fe23e31b009c9886b2d0fb8b2/pyyaml-6.0.3-cp312-cp312-macosx_10_13_x86_64.whl", using: :nounzip
      sha256 "7f047e29dcae44602496db43be01ad42fc6f1cc0d8cd6c83d342306c32270196"
    end
    resource "referencing" do
      url "https://files.pythonhosted.org/packages/2c/58/ca301544e1fa93ed4f80d724bf5b194f6e4b945841c5bfd555878eea9fcb/referencing-0.37.0-py3-none-any.whl", using: :nounzip
      sha256 "381329a9f99628c9069361716891d34ad94af76e461dcb0335825aecc7692231"
    end
    resource "regex" do
      url "https://files.pythonhosted.org/packages/2e/1c/4ee3e97c76f53940488dfe7a7e18705e78daac8cd7fb161d246b9e328449/regex-2026.9.29-cp312-cp312-macosx_10_13_x86_64.whl", using: :nounzip
      sha256 "3a21a9509d0ee88e7a70e1ad228cd2f0e0fd1e187458db132e8a8d18c97daf9d"
    end
    resource "requests" do
      url "https://files.pythonhosted.org/packages/a0/f4/c67b0b3f1b9245e8d266f0f112c500d50e5b4e83cb6f3b71b6528104182a/requests-2.34.2-py3-none-any.whl", using: :nounzip
      sha256 "2a0d60c172f83ac6ab31e4554906c0f3b3588d37b5cb939b1c061f4907e278e0"
    end
    resource "rich" do
      url "https://files.pythonhosted.org/packages/b3/76/6d163cfac87b632216f71879e6b2cf17163f773ff59c00b5ff4900a80fa3/rich-14.3.4-py3-none-any.whl", using: :nounzip
      sha256 "07e7adb4690f68864777b1450859253bed81a99a31ac321ac1817b2313558952"
    end
    resource "rpds-py" do
      url "https://files.pythonhosted.org/packages/5d/34/a828586ea3329fbb50895b50e9cf98ca3d924a9f41a0b26d443bff1b3794/rpds_py-2026.9.1-cp312-cp312-macosx_10_12_x86_64.whl", using: :nounzip
      sha256 "50906f5aea24b5a865cbd0a589698288631d9f3a54c3a937c83aefa95a0d14af"
    end
    resource "s3transfer" do
      url "https://files.pythonhosted.org/packages/e2/a4/88f9e10498759121060b8050a1554753dfc04df39bbbcc7aad9ecc8d9440/s3transfer-0.19.3-py3-none-any.whl", using: :nounzip
      sha256 "24eb7535804306355e31c952a90022bf5b2f9d760f9a11062c7493a217c08553"
    end
    resource "setuptools" do
      url "https://files.pythonhosted.org/packages/ef/55/6dc6d6bb953bdfc52519a0059592c52b6e3b8ad51cf8256dffceb55b0610/setuptools-84.2.1-py3-none-any.whl", using: :nounzip
      sha256 "ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2"
    end
    resource "setuptools-scm" do
      url "https://files.pythonhosted.org/packages/da/f5/54538a1f17ea753c42b0928dc2e62986d463f8c393340b9a1e602f2d4dd9/setuptools_scm-10.3.4-py3-none-any.whl", using: :nounzip
      sha256 "82f34c3e3084fc2b57d397200637cc13f2338004052d2fee47baa5f0e902464e"
    end
    resource "six" do
      url "https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl", using: :nounzip
      sha256 "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274"
    end
    resource "sniffio" do
      url "https://files.pythonhosted.org/packages/e9/44/75a9c9421471a6c4805dbf2356f7c181a29c1879239abab1ea2cc8f38b40/sniffio-1.3.1-py3-none-any.whl", using: :nounzip
      sha256 "2f6da418d1f1e0fddd844478f41680e794e6051915791a034ff65e5f100525a2"
    end
    resource "starlette" do
      url "https://files.pythonhosted.org/packages/f3/93/181df62699d9b5aca1d87e5cfda131dac87e3cdaebf668662f7206ca3470/starlette-1.9.0-py3-none-any.whl", using: :nounzip
      sha256 "fd3f159936e882d06c1108f84688f7cda2cf85fc6a592a50edbd175e882c2ddc"
    end
    resource "sympy" do
      url "https://files.pythonhosted.org/packages/a2/09/77d55d46fd61b4a135c444fc97158ef34a095e5681d0a6c10b75bf356191/sympy-1.14.0-py3-none-any.whl", using: :nounzip
      sha256 "e091cc3e99d2141a0ba2847328f5479b05d94a6635cb96148ccb3f34671bd8f5"
    end
    resource "tabulate" do
      url "https://files.pythonhosted.org/packages/99/55/db07de81b5c630da5cbf5c7df646580ca26dfaefa593667fc6f2fe016d2e/tabulate-0.10.0-py3-none-any.whl", using: :nounzip
      sha256 "f0b0622e567335c8fabaaa659f1b33bcb6ddfe2e496071b743aa113f8774f2d3"
    end
    resource "textual" do
      url "https://files.pythonhosted.org/packages/fb/be/35261223d9416a0751cdff1c7b4a6f881387218a12d439fe22fefebc8c04/textual-8.2.8-py3-none-any.whl", using: :nounzip
      sha256 "267375fd402dc8d981457212efa71f0e3365fd17bba144ba9bb3ed7563cb374a"
    end
    resource "tiktoken" do
      url "https://files.pythonhosted.org/packages/8c/da/e273746b9d24a63c776bc60fba914351573ad9c575b52601eb5e60632564/tiktoken-0.14.0-cp312-cp312-macosx_10_13_x86_64.whl", using: :nounzip
      sha256 "8e947aefe98ef74cce94923f90e48c98fe34eb1ec0a6bfdfadfc5a96359bfc36"
    end
    resource "tokenizers" do
      url "https://files.pythonhosted.org/packages/aa/2e/4ce5b9716f26e526eff6b0502ebed4ea8d7161f03b3c77617c9f25528e97/tokenizers-0.23.3-cp310-abi3-macosx_10_12_x86_64.whl", using: :nounzip
      sha256 "9d2b5c97daf61688c2ad1803ca851800feaba50fb68d5821779e9ea5880d968c"
    end
    resource "tomlkit" do
      url "https://files.pythonhosted.org/packages/da/46/7d84138a60a8bd796825b2d38ebe92d0d16501ca57d501b7c5d677401bbc/tomlkit-0.15.2-py3-none-any.whl", using: :nounzip
      sha256 "05562412163a3037b94497385fb7f9204c637bc605af7a48199e41cf2272f437"
    end
    resource "tqdm" do
      url "https://files.pythonhosted.org/packages/a7/03/921a3d3c75785aca9ebfbfcabfbc3a1be12e2ab5265deb026d55a5a3f83e/tqdm-4.70.1-py3-none-any.whl", using: :nounzip
      sha256 "c293e525e6fef9c20e8728fd4612df02a0aa31bb5fe91ecd93e123b1b7bffa73"
    end
    resource "trove-classifiers" do
      url "https://files.pythonhosted.org/packages/30/81/0da8afb52a71d0a4f2bd3152357b1a441e393b286374802b9d3addab4ab5/trove_classifiers-2026.9.21.13-py3-none-any.whl", using: :nounzip
      sha256 "8b1ff4f9c191b1040b71c37f1e445ab99732911e3cd91de52838453a854d7a17"
    end
    resource "typing-extensions" do
      url "https://files.pythonhosted.org/packages/49/d3/b8441a820a491ddfc024b0b0cf0393375b75ea13866d9c66727e54c2fc80/typing_extensions-4.16.0-py3-none-any.whl", using: :nounzip
      sha256 "481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8"
    end
    resource "typing-inspection" do
      url "https://files.pythonhosted.org/packages/67/81/4add07e5172b7ac40d8ed5ff580409a7801a4fe26d529bdd915401dabfbe/typing_inspection-0.4.4-py3-none-any.whl", using: :nounzip
      sha256 "65b8397ba37ccbce054456aaccddfc91e6e3083c92824df348d96ca832f3f147"
    end
    resource "urllib3" do
      url "https://files.pythonhosted.org/packages/92/9d/c4e665119135114480843e7ab388fa94d8480650450e6f8e26b70d323a4c/urllib3-2.8.0-py3-none-any.whl", using: :nounzip
      sha256 "0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3"
    end
    resource "uvicorn" do
      url "https://files.pythonhosted.org/packages/38/0c/b54a4fdd7f90a3af8b02ebc9ce6712c2c208b7926a2f7bad95c33ebbe943/uvicorn-0.54.0-py3-none-any.whl", using: :nounzip
      sha256 "505bdb0f318731d45f1f712071fc781a8981f6847a31c902c9f5e652d4f67faf"
    end
    resource "uvloop" do
      url "https://files.pythonhosted.org/packages/33/8a/499e7b863a848ede009539bce39806b66205da5f8779354228e785601144/uvloop-0.23.0-cp312-cp312-macosx_10_13_x86_64.whl", using: :nounzip
      sha256 "4448e9124537620f9c25d004c227bb5104440b58955c19bbd312d910af919a63"
    end
    resource "vcs-versioning" do
      url "https://files.pythonhosted.org/packages/73/1d/ad4064bf12f4503bf61e65d74c93c523672776d25ee0a06aaf42ae09ef3f/vcs_versioning-2.6.0-py3-none-any.whl", using: :nounzip
      sha256 "f8bebd1302ebc12e67ceb30fc7dd698ec969414b6fa43b30c3f14ac9b1e72c41"
    end
    resource "watchfiles" do
      url "https://files.pythonhosted.org/packages/68/fa/c0b840d5d8bafe640925408ce11095948c8945bb61be1e67d0ab629b872a/watchfiles-1.3.0-cp310-abi3-macosx_10_12_x86_64.whl", using: :nounzip
      sha256 "000b9688fc8133037a8b075c8ebf98f32844ff8964dda61e85c1db547dafc441"
    end
    resource "websockets" do
      url "https://files.pythonhosted.org/packages/d7/b0/3f01fcb3406662f6deb1e3e72b34dd0979e993991c0b7435a9e12bc14f02/websockets-17.3-py3-none-any.whl", using: :nounzip
      sha256 "dc2b495a92b3971966bf102e73589f950db3ec1ca6713265355ce7771d97b199"
    end
    resource "yara-x" do
      url "https://files.pythonhosted.org/packages/69/19/0365004e652a44dfccaa2fc73916b6c8e5ac0e64bbae1c0dfc301c5bdd63/yara_x-1.22.0-cp39-abi3-macosx_14_0_x86_64.whl", using: :nounzip
      sha256 "1472591e7ec4a07be0e63383235fc2e8908b6d7d510b98d210068ffde30bbe10"
    end
    resource "yarl" do
      url "https://files.pythonhosted.org/packages/54/22/318c7980066769c6bcd9221ed2248294f5698811da099013098c670565ed/yarl-1.25.1-py3-none-any.whl", using: :nounzip
      sha256 "681c758b0490f9e96b78e5fa8e8dc6e648e9185bb6eaebe73183c33ea0c445f3"
    end
    resource "zipp" do
      url "https://files.pythonhosted.org/packages/b5/98/df615823cd9419131ce19fba00de53a663794369e198aade064a244b385d/zipp-4.1.1-py3-none-any.whl", using: :nounzip
      sha256 "8979f52d874162f485ff2981e3891f3a3317b7a3dd43ff1e1775b9304f307a9c"
    end
  end



  def install
    ENV["PIP_NO_INDEX"] = "1"
    ENV["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    ENV["SKILL_SCANNER_CEL_GO_TARGET"] = Hardware::CPU.arm? ? "darwin-arm64" : "darwin-amd64"
    helper_dir = buildpath/"cel-helper"
    resource("cel-helper").stage do
      # Homebrew stages .whl resources without extracting them; extract
      # only the helper bundle, and accept an already-extracted tree too.
      wheel = Pathname.glob("*.whl").first
      if wheel
        system "unzip", "-q", wheel, "skill_scanner/core/cel/_bin/*", "-d", helper_dir
      else
        helper_dir.install Pathname.pwd.children
      end
    end
    ENV["SKILL_SCANNER_CEL_GO_PREBUILT_DIR"] = helper_dir/"skill_scanner/core/cel/_bin"
    venv = virtualenv_create(libexec, "python3.12")
    dependency_resources = resources.reject { |resource| resource.name == "cel-helper" }
    wheelhouse = buildpath/"dependency-wheelhouse"
    wheelhouse.mkpath
    dependency_resources.each { |resource| resource.stage(wheelhouse) }
    dependency_wheels = wheelhouse.children.sort
    odie "Dependency wheelhouse is incomplete" unless dependency_wheels.length == dependency_resources.length &&
                                                   dependency_wheels.all? { |wheel| wheel.file? && wheel.extname == ".whl" }
    venv.pip_install dependency_wheels.join("\n"), build_isolation: false
    venv.pip_install_and_link buildpath, build_isolation: false
  end

  test do
    assert_match "usage:", shell_output("#{bin}/skill-scanner --help")
    system "#{bin}/skill-scanner", "validate-rules"
  end
end
