class SkillScanner < Formula
  include Language::Python::Virtualenv

  desc "Security scanner for AI Agent Skills and MCP servers"
  homepage "https://github.com/cisco-ai-defense/skill-scanner"
  url "https://files.pythonhosted.org/packages/d6/3b/7a8b1f57e97b815b64f771b98e4f3021ac31a74c35f95b1472192553225b/cisco_ai_skill_scanner-2.2.0.tar.gz"
  sha256 "f9748573cb0c961a75da1d1153509e4b5dfdffbe1b7796b142173a4bdebddb7c"
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
      url "https://files.pythonhosted.org/packages/39/72/e1d4b5e67e07f9848a08092efe344f597c67e40e20a3361a9e8db8629a64/cisco_ai_skill_scanner-2.2.0-cp311.cp312.cp313.cp314-none-macosx_13_0_arm64.whl"
      sha256 "7f65fd1ac9857eb6e4b7b1c528bb040b9ee4a2dd911cfb2817fc9e30cfcd00c4"
    end
    resource "aiohappyeyeballs" do
      url "https://files.pythonhosted.org/packages/71/43/1947f06babed6b3f1d7f38b0c767f52df66bfb2bc10b468c4a7de9eceff2/aiohappyeyeballs-2.7.1-py3-none-any.whl", using: :nounzip
      sha256 "9243213661e29250eb41368e5daa826fc017156c3b8a11440826b2e3ed376472"
    end
    resource "aiohttp" do
      url "https://files.pythonhosted.org/packages/18/d4/eb96299230e20acf2efae207cb8d69051f1f68e357e5ea5e479bf6fb097a/aiohttp-3.14.3-cp312-cp312-macosx_10_13_universal2.whl", using: :nounzip
      sha256 "39aded8c7f3b935b54aab1d8d73c70ec0ee2d3ec3b943e0e86611bc150ba47f5"
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
      url "https://files.pythonhosted.org/packages/74/e4/7e88c40e9f61888e12dac0de41a5fddc2bcd1c3992d9b28e17d915cce0df/boto3-1.43.108-py3-none-any.whl", using: :nounzip
      sha256 "19e9da95ef0c494e27052049a42137550e66730509bb613e76eaa30ddf9a7170"
    end
    resource "botocore" do
      url "https://files.pythonhosted.org/packages/7a/0b/4670b7e23914b5cc357be5ca45fae503b57d98ecff4b3eabea70412809fd/botocore-1.43.108-py3-none-any.whl", using: :nounzip
      sha256 "ab9d16c6b4350aaa54ed28202dfa2998b2d735fdbf3247eb60af469d8d48a5b8"
    end
    resource "certifi" do
      url "https://files.pythonhosted.org/packages/0b/a7/71ac2cff56fec219ed242bb11b8efb69fcc4bec75db06fb7bfe35de520e6/certifi-2026.7.22-py3-none-any.whl", using: :nounzip
      sha256 "62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775"
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
      url "https://files.pythonhosted.org/packages/a0/b6/78aaf9141fb46742928c113f3cf6ef2259d538cb02b604b7656c1dc9883c/fastapi-0.142.2-py3-none-any.whl", using: :nounzip
      sha256 "bd5f4d81f1e93a88bcd77caf4dfe3c2dbffc3805407a0007e9a114c18b3a670b"
    end
    resource "fastuuid" do
      url "https://files.pythonhosted.org/packages/02/a2/e78fcc5df65467f0d207661b7ef86c5b7ac62eea337c0c0fcedbeee6fb13/fastuuid-0.14.0-cp312-cp312-macosx_10_12_x86_64.macosx_11_0_arm64.macosx_10_12_universal2.whl", using: :nounzip
      sha256 "77e94728324b63660ebf8adb27055e92d2e4611645bf12ed9d88d30486471d0a"
    end
    resource "filelock" do
      url "https://files.pythonhosted.org/packages/01/4f/83454fafd628e1e7e1726d74e44fb2332be5969d04c6182ca1fecb6c580e/filelock-4.0.9-py3-none-any.whl", using: :nounzip
      sha256 "9287fd61b99a806e5202be29a83034c0808a1b9830e820537c2f5773981f7eeb"
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
      url "https://files.pythonhosted.org/packages/4b/69/55b8dcf636142ae660fec1869fcac14c4da2e8412e14d6eee1523be77e9f/hf_xet-1.6.0-cp38-abi3-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "f0906082d9932ae0c0057fa194041c22b4e2cdb46b2592ef3b91f020d62a081a"
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
      url "https://files.pythonhosted.org/packages/14/88/1d21a36da8f5cb0fa49eafd4b169eba5608d57e75bbcf61845cbc6243216/httptools-0.8.0-cp312-cp312-macosx_10_13_universal2.whl", using: :nounzip
      sha256 "880490234c10f70a9830743097e8958d6e4b9f5a0ffc24515023afeef984054d"
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
      url "https://files.pythonhosted.org/packages/32/75/6ee7223edc0da9fda4cd1804dbfb7f7cd1d1e62bf608b002b7fb72b97c6b/litellm-1.103.2-cp310-abi3-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "2dc9ebb340a9b3ba0e0a72e6ba86d28b702f5489e53eb6ef96c5831fcaa50108"
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
      url "https://files.pythonhosted.org/packages/9a/81/7e4e08678a1f98521201c3079f77db69fb552acd56067661f8c2f534a718/markupsafe-3.0.3-cp312-cp312-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "1872df69a4de6aead3491198eaf13810b565bdbeec3ae2dc8780f14458ec73ce"
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
      url "https://files.pythonhosted.org/packages/be/59/e26cb779be4c591d1a910f59d29aca9fba4de70349840a833beba2652371/multidict-6.9.1-py3-none-any.whl", using: :nounzip
      sha256 "7bf6478188f4e47bf5686e8a33da4ae28bf43b1b2528d9ee144d28492bfac60b"
    end
    resource "numpy" do
      url "https://files.pythonhosted.org/packages/60/39/789131c1188c078dcb3a1692e72e1e050c68b88ffe72c9ccaac9bcd7a9cd/numpy-2.5.3-cp312-cp312-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "f59a878c33d6b88122d80d239bb3b845d58708750b0cb06a09aebb9b18ec696c"
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
      url "https://files.pythonhosted.org/packages/31/6f/48169f2e62b405bff5053cbd1d73fb5ce41ef7ecd13bb3bfcc191e689b8a/onnxruntime-1.30.0-cp312-cp312-macosx_14_0_arm64.whl", using: :nounzip
      sha256 "001ed726c9bd5e2bc92faade7d37d889e9606a350b7d5529f0227df2e3bb57fd"
    end
    resource "openai" do
      url "https://files.pythonhosted.org/packages/64/a8/bb76c7356de8ad57f59d5ff993d434df0607f07f08bcc9c9a5c275e399c0/openai-2.54.0-py3-none-any.whl", using: :nounzip
      sha256 "89089789197ccdb87f173a03145ed1598d00795220c93e96cf712b1cbf5e5f2b"
    end
    resource "opentelemetry-api" do
      url "https://files.pythonhosted.org/packages/44/b9/040d1a1c7836922828e6480cd2366bb8fe0ebf75b413d2bb51a9b0e7f78f/opentelemetry_api-1.45.0-py3-none-any.whl", using: :nounzip
      sha256 "80e068aba7cd56c8b58512d6a36f8d25cb1dfaa0c0a4cc1c938ccf9f362d9cb3"
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
      url "https://files.pythonhosted.org/packages/d0/89/446044f33aba0348d35e433f56d12206d010a5281a1df54054d4cfb82388/platformdirs-4.12.2-py3-none-any.whl", using: :nounzip
      sha256 "29dbf06d96c500bc6bdbce75fb0a14d63279c93b1842f97e72a135b33e856983"
    end
    resource "pluggy" do
      url "https://files.pythonhosted.org/packages/54/20/4d324d65cc6d9205fabedc306948156824eb9f0ee1633355a8f7ec5c66bf/pluggy-1.6.0-py3-none-any.whl", using: :nounzip
      sha256 "e920276dd6813095e9377c0bc5566d94c932c33b27a3e3945d8389c374dd4746"
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
      url "https://files.pythonhosted.org/packages/0c/c3/44f3fbbfa403ea2a7c779186dc20772604442dde72947e7d01069cbe98e3/pycparser-3.0-py3-none-any.whl", using: :nounzip
      sha256 "b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992"
    end
    resource "pydantic" do
      url "https://files.pythonhosted.org/packages/eb/47/c95ffc2009878c7aac0c5e08528022dcb885933252a88b5f170058014464/pydantic-2.13.5-py3-none-any.whl", using: :nounzip
      sha256 "346a034f080da3755d8e9cb5e00e8b07de1d39e4f6e2c87d8ab7cafa0b269a73"
    end
    resource "pydantic_core" do
      url "https://files.pythonhosted.org/packages/db/50/26b091836076ce4cb2fac264186936acc069e0595772cfd02a563bc4761a/pydantic_core-2.46.5-cp312-cp312-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "a39ac25a9a2fa4072efdb429833c4a4c8009a51ff9eea3eeae131713cd27991e"
    end
    resource "pydantic-settings" do
      url "https://files.pythonhosted.org/packages/30/a4/2bffa9f8e804325a09867f0e9d30795c80ea9f8d62560bd1b6ad6220eb2f/pydantic_settings-2.15.0-py3-none-any.whl", using: :nounzip
      sha256 "0ba092c291c94baceb5eff768aa0d56400a457585bc0175925a5a5510303da42"
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
      url "https://files.pythonhosted.org/packages/a4/73/319dfa745dd668efe89309141ded489126461fcecd2b8f3a3cda185129b6/rpds_py-2026.6.3-cp312-cp312-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "538949e262e46caa31ac01bdb3c1e8f642622922cacbabbae6a8445d9dc33eaf"
    end
    resource "s3transfer" do
      url "https://files.pythonhosted.org/packages/bc/e7/5c595c75e9f41a44f30e526eda465ea0b4eec93470e074e4a111b253f13a/s3transfer-0.19.2-py3-none-any.whl", using: :nounzip
      sha256 "d8168eccca828cbb2cd573675333f3bddd254313a9c42494b84c76b539e8ba25"
    end
    resource "setuptools" do
      url "https://files.pythonhosted.org/packages/95/9c/c510029fc6ef33a6275cd2c5d3cecd6613dfd6aa401d57c54f1c18852ccf/setuptools-84.0.0-py3-none-any.whl", using: :nounzip
      sha256 "51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670"
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
      url "https://files.pythonhosted.org/packages/4e/d6/1ec1b290f9e0fb067899b61e1d37a30c923068bad260b216dbe37a7d2967/starlette-1.7.0-py3-none-any.whl", using: :nounzip
      sha256 "67f8e99895493dd2911a03f11314af6ceebeae4e704bb9f43dfc6a9db151c93e"
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
      url "https://files.pythonhosted.org/packages/67/49/22da045a91732384d3a3771816bf188dc5a1f702c32e635afa7c679c0bef/tokenizers-0.23.2-cp310-abi3-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "986670e43691469dcee610ea0f846f91a8f84e91fc6f7a48d4c064414c0ec2bf"
    end
    resource "tomlkit" do
      url "https://files.pythonhosted.org/packages/13/bc/8c13eb66537dce1d2bd3a57132902f38d0e7f5bb46fa9f4daed9fe9d76ee/tomlkit-0.15.1-py3-none-any.whl", using: :nounzip
      sha256 "177a05aece5a8ca5266fd3c448abb47b8d352f09d477d3ca8332db4d89b24304"
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
      url "https://files.pythonhosted.org/packages/e4/e6/b4dedd1efea8a1e432123575896328dec83c26327164f7098db415d13f6f/vcs_versioning-2.5.0-py3-none-any.whl", using: :nounzip
      sha256 "dbf44f6303dc817e5792cb7d0e9cc90e3046ee1e32eaa357b20ad368811313d0"
    end
    resource "watchfiles" do
      url "https://files.pythonhosted.org/packages/c7/8a/894799b485fe9473ad10422a0d9668e53fb78e3a2b5cc6061159572844ad/watchfiles-1.3.0-cp310-abi3-macosx_11_0_arm64.whl", using: :nounzip
      sha256 "bbc1198edfdc90fda0600f825aa94150f428dfcbf8138746f55998e0e660d64c"
    end
    resource "websockets" do
      url "https://files.pythonhosted.org/packages/41/63/23572870e01836a98346075b9e17a8bc24a6ddd9800a3204ceee58677f3c/websockets-17.1-py3-none-any.whl", using: :nounzip
      sha256 "f221081107b8c48184d99f7019604486376e7ef826037e70aad6b02540732c23"
    end
    resource "yara-x" do
      url "https://files.pythonhosted.org/packages/ea/f3/d5646eabcd9d3920a5bcf77de64077df7e88f245842a4ac555d12280a220/yara_x-1.21.0-cp38-abi3-macosx_14_0_arm64.whl", using: :nounzip
      sha256 "24a739f492782335bb3b886cb2b6eaf008991f67b9e63e15b940af02aba233c0"
    end
    resource "yarl" do
      url "https://files.pythonhosted.org/packages/54/22/318c7980066769c6bcd9221ed2248294f5698811da099013098c670565ed/yarl-1.25.1-py3-none-any.whl", using: :nounzip
      sha256 "681c758b0490f9e96b78e5fa8e8dc6e648e9185bb6eaebe73183c33ea0c445f3"
    end
    resource "zipp" do
      url "https://files.pythonhosted.org/packages/3a/13/547360d81e6d88d58492968ffda9f9542854f11310ee556fef14260cc886/zipp-4.1.0-py3-none-any.whl", using: :nounzip
      sha256 "25ad4e16390cd314347dd8f1de67a2ac538ae658ed4ab9db16029c07c188e97f"
    end
  end
  on_intel do
    resource "cel-helper" do
      url "https://files.pythonhosted.org/packages/08/ef/7389a10c51a2b10d33e0dad666624a54f7086b7a10de487beb0542a39527/cisco_ai_skill_scanner-2.2.0-cp311.cp312.cp313.cp314-none-macosx_13_0_x86_64.whl"
      sha256 "0c90bf21533710b86b081e844f5522afac96e1ab60cdd726ca16236d2deb9708"
    end
    resource "aiohappyeyeballs" do
      url "https://files.pythonhosted.org/packages/71/43/1947f06babed6b3f1d7f38b0c767f52df66bfb2bc10b468c4a7de9eceff2/aiohappyeyeballs-2.7.1-py3-none-any.whl", using: :nounzip
      sha256 "9243213661e29250eb41368e5daa826fc017156c3b8a11440826b2e3ed376472"
    end
    resource "aiohttp" do
      url "https://files.pythonhosted.org/packages/88/11/e7a70a209eb9a067c0d3212b518a0134e3484f5178c7533878b6b514d469/aiohttp-3.14.3-cp312-cp312-macosx_10_13_x86_64.whl", using: :nounzip
      sha256 "5bcb6ff3fdab1258a192679ff1a05d44f59626430aa05cd1a9d2447423599228"
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
      url "https://files.pythonhosted.org/packages/74/e4/7e88c40e9f61888e12dac0de41a5fddc2bcd1c3992d9b28e17d915cce0df/boto3-1.43.108-py3-none-any.whl", using: :nounzip
      sha256 "19e9da95ef0c494e27052049a42137550e66730509bb613e76eaa30ddf9a7170"
    end
    resource "botocore" do
      url "https://files.pythonhosted.org/packages/7a/0b/4670b7e23914b5cc357be5ca45fae503b57d98ecff4b3eabea70412809fd/botocore-1.43.108-py3-none-any.whl", using: :nounzip
      sha256 "ab9d16c6b4350aaa54ed28202dfa2998b2d735fdbf3247eb60af469d8d48a5b8"
    end
    resource "certifi" do
      url "https://files.pythonhosted.org/packages/0b/a7/71ac2cff56fec219ed242bb11b8efb69fcc4bec75db06fb7bfe35de520e6/certifi-2026.7.22-py3-none-any.whl", using: :nounzip
      sha256 "62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775"
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
      url "https://files.pythonhosted.org/packages/a0/b6/78aaf9141fb46742928c113f3cf6ef2259d538cb02b604b7656c1dc9883c/fastapi-0.142.2-py3-none-any.whl", using: :nounzip
      sha256 "bd5f4d81f1e93a88bcd77caf4dfe3c2dbffc3805407a0007e9a114c18b3a670b"
    end
    resource "fastuuid" do
      url "https://files.pythonhosted.org/packages/02/a2/e78fcc5df65467f0d207661b7ef86c5b7ac62eea337c0c0fcedbeee6fb13/fastuuid-0.14.0-cp312-cp312-macosx_10_12_x86_64.macosx_11_0_arm64.macosx_10_12_universal2.whl", using: :nounzip
      sha256 "77e94728324b63660ebf8adb27055e92d2e4611645bf12ed9d88d30486471d0a"
    end
    resource "filelock" do
      url "https://files.pythonhosted.org/packages/01/4f/83454fafd628e1e7e1726d74e44fb2332be5969d04c6182ca1fecb6c580e/filelock-4.0.9-py3-none-any.whl", using: :nounzip
      sha256 "9287fd61b99a806e5202be29a83034c0808a1b9830e820537c2f5773981f7eeb"
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
      url "https://files.pythonhosted.org/packages/a2/50/7afa2c9c787405864fc47a0d1bbc02c62e9101947ed43c1f43899fc7d91d/hf_xet-1.6.0-cp38-abi3-macosx_10_12_x86_64.whl", using: :nounzip
      sha256 "633dc0cd71d32da58ab8c03ad38e2fac452c15c2b0a2866ebf6ededfe0a5061d"
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
      url "https://files.pythonhosted.org/packages/14/88/1d21a36da8f5cb0fa49eafd4b169eba5608d57e75bbcf61845cbc6243216/httptools-0.8.0-cp312-cp312-macosx_10_13_universal2.whl", using: :nounzip
      sha256 "880490234c10f70a9830743097e8958d6e4b9f5a0ffc24515023afeef984054d"
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
      url "https://files.pythonhosted.org/packages/a9/d2/5d721cc501d48850caf76f0bf6eb5b179e76b8720663d626c465fd92d1a6/litellm-1.103.2-cp310-abi3-macosx_10_12_x86_64.whl", using: :nounzip
      sha256 "ff38483d5dd7384e285aaec0d60ce4b0924a5c14f7250af6549baac409ca4150"
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
      url "https://files.pythonhosted.org/packages/5a/72/147da192e38635ada20e0a2e1a51cf8823d2119ce8883f7053879c2199b5/markupsafe-3.0.3-cp312-cp312-macosx_10_13_x86_64.whl", using: :nounzip
      sha256 "d53197da72cc091b024dd97249dfc7794d6a56530370992a5e1a08983ad9230e"
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
      url "https://files.pythonhosted.org/packages/be/59/e26cb779be4c591d1a910f59d29aca9fba4de70349840a833beba2652371/multidict-6.9.1-py3-none-any.whl", using: :nounzip
      sha256 "7bf6478188f4e47bf5686e8a33da4ae28bf43b1b2528d9ee144d28492bfac60b"
    end
    resource "numpy" do
      url "https://files.pythonhosted.org/packages/d6/50/8fdbb16af64895706a45f06a4068e29db732ec180f3c1375f14123359138/numpy-2.5.3-cp312-cp312-macosx_10_13_x86_64.whl", using: :nounzip
      sha256 "cb189f09db39283b26bfd061ec16189e14f71c6755207f72a0f7540867afe5b9"
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
      url "https://files.pythonhosted.org/packages/44/b9/040d1a1c7836922828e6480cd2366bb8fe0ebf75b413d2bb51a9b0e7f78f/opentelemetry_api-1.45.0-py3-none-any.whl", using: :nounzip
      sha256 "80e068aba7cd56c8b58512d6a36f8d25cb1dfaa0c0a4cc1c938ccf9f362d9cb3"
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
      url "https://files.pythonhosted.org/packages/d0/89/446044f33aba0348d35e433f56d12206d010a5281a1df54054d4cfb82388/platformdirs-4.12.2-py3-none-any.whl", using: :nounzip
      sha256 "29dbf06d96c500bc6bdbce75fb0a14d63279c93b1842f97e72a135b33e856983"
    end
    resource "pluggy" do
      url "https://files.pythonhosted.org/packages/54/20/4d324d65cc6d9205fabedc306948156824eb9f0ee1633355a8f7ec5c66bf/pluggy-1.6.0-py3-none-any.whl", using: :nounzip
      sha256 "e920276dd6813095e9377c0bc5566d94c932c33b27a3e3945d8389c374dd4746"
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
      url "https://files.pythonhosted.org/packages/0c/c3/44f3fbbfa403ea2a7c779186dc20772604442dde72947e7d01069cbe98e3/pycparser-3.0-py3-none-any.whl", using: :nounzip
      sha256 "b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992"
    end
    resource "pydantic" do
      url "https://files.pythonhosted.org/packages/eb/47/c95ffc2009878c7aac0c5e08528022dcb885933252a88b5f170058014464/pydantic-2.13.5-py3-none-any.whl", using: :nounzip
      sha256 "346a034f080da3755d8e9cb5e00e8b07de1d39e4f6e2c87d8ab7cafa0b269a73"
    end
    resource "pydantic_core" do
      url "https://files.pythonhosted.org/packages/82/3f/76358795aa7a8c6d4f36e2cb828ad1c90ee118e1393a9281664f5aade9d4/pydantic_core-2.46.5-cp312-cp312-macosx_10_12_x86_64.whl", using: :nounzip
      sha256 "b9fe6fb92520e3fd61f2e49000b6911b188824f089b75973ea06d6267f0b476d"
    end
    resource "pydantic-settings" do
      url "https://files.pythonhosted.org/packages/30/a4/2bffa9f8e804325a09867f0e9d30795c80ea9f8d62560bd1b6ad6220eb2f/pydantic_settings-2.15.0-py3-none-any.whl", using: :nounzip
      sha256 "0ba092c291c94baceb5eff768aa0d56400a457585bc0175925a5a5510303da42"
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
      url "https://files.pythonhosted.org/packages/5c/be/2e8974163072e7bab7df1a5acd54c4498e75e35d6d18b864d3a9d5dadc92/rpds_py-2026.6.3-cp312-cp312-macosx_10_12_x86_64.whl", using: :nounzip
      sha256 "a0811d33247c3d6128a3001d763f2aa056bb3425204335400ac54f89eec3a0d0"
    end
    resource "s3transfer" do
      url "https://files.pythonhosted.org/packages/bc/e7/5c595c75e9f41a44f30e526eda465ea0b4eec93470e074e4a111b253f13a/s3transfer-0.19.2-py3-none-any.whl", using: :nounzip
      sha256 "d8168eccca828cbb2cd573675333f3bddd254313a9c42494b84c76b539e8ba25"
    end
    resource "setuptools" do
      url "https://files.pythonhosted.org/packages/95/9c/c510029fc6ef33a6275cd2c5d3cecd6613dfd6aa401d57c54f1c18852ccf/setuptools-84.0.0-py3-none-any.whl", using: :nounzip
      sha256 "51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670"
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
      url "https://files.pythonhosted.org/packages/4e/d6/1ec1b290f9e0fb067899b61e1d37a30c923068bad260b216dbe37a7d2967/starlette-1.7.0-py3-none-any.whl", using: :nounzip
      sha256 "67f8e99895493dd2911a03f11314af6ceebeae4e704bb9f43dfc6a9db151c93e"
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
      url "https://files.pythonhosted.org/packages/4d/ed/8a443528baa6fac8dfe8c3b75b038c63ac92bb539bcabe311e227c718173/tokenizers-0.23.2-cp310-abi3-macosx_10_12_x86_64.whl", using: :nounzip
      sha256 "85a9a357a3764aecc904ee76bdaf8cf1ad8e5a67a1b929a487c4a39b49ed0e90"
    end
    resource "tomlkit" do
      url "https://files.pythonhosted.org/packages/13/bc/8c13eb66537dce1d2bd3a57132902f38d0e7f5bb46fa9f4daed9fe9d76ee/tomlkit-0.15.1-py3-none-any.whl", using: :nounzip
      sha256 "177a05aece5a8ca5266fd3c448abb47b8d352f09d477d3ca8332db4d89b24304"
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
      url "https://files.pythonhosted.org/packages/e4/e6/b4dedd1efea8a1e432123575896328dec83c26327164f7098db415d13f6f/vcs_versioning-2.5.0-py3-none-any.whl", using: :nounzip
      sha256 "dbf44f6303dc817e5792cb7d0e9cc90e3046ee1e32eaa357b20ad368811313d0"
    end
    resource "watchfiles" do
      url "https://files.pythonhosted.org/packages/68/fa/c0b840d5d8bafe640925408ce11095948c8945bb61be1e67d0ab629b872a/watchfiles-1.3.0-cp310-abi3-macosx_10_12_x86_64.whl", using: :nounzip
      sha256 "000b9688fc8133037a8b075c8ebf98f32844ff8964dda61e85c1db547dafc441"
    end
    resource "websockets" do
      url "https://files.pythonhosted.org/packages/41/63/23572870e01836a98346075b9e17a8bc24a6ddd9800a3204ceee58677f3c/websockets-17.1-py3-none-any.whl", using: :nounzip
      sha256 "f221081107b8c48184d99f7019604486376e7ef826037e70aad6b02540732c23"
    end
    resource "yara-x" do
      url "https://files.pythonhosted.org/packages/6f/6b/362a34a3cfe186fb5a956d65c1f1c98fd14d8f8dfb322211c72c9bb6ab19/yara_x-1.21.0-cp38-abi3-macosx_14_0_x86_64.whl", using: :nounzip
      sha256 "1c6e15cf61500bc27960099872586d41f3cfdd8597e4bb8d2f0361b921b118d9"
    end
    resource "yarl" do
      url "https://files.pythonhosted.org/packages/54/22/318c7980066769c6bcd9221ed2248294f5698811da099013098c670565ed/yarl-1.25.1-py3-none-any.whl", using: :nounzip
      sha256 "681c758b0490f9e96b78e5fa8e8dc6e648e9185bb6eaebe73183c33ea0c445f3"
    end
    resource "zipp" do
      url "https://files.pythonhosted.org/packages/3a/13/547360d81e6d88d58492968ffda9f9542854f11310ee556fef14260cc886/zipp-4.1.0-py3-none-any.whl", using: :nounzip
      sha256 "25ad4e16390cd314347dd8f1de67a2ac538ae658ed4ab9db16029c07c188e97f"
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
