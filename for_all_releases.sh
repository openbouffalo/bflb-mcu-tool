#!/bin/bash

wget https://files.pythonhosted.org/packages/c5/06/ae5665469e31a6375ffa82ba8aa7db6b8d588d8f94234ae812a89a0c06be/bflb-mcu-tool-1.0.0.tar.gz
wget https://files.pythonhosted.org/packages/f8/8d/61b5f74fd67a9c8cc3f6231e25890e1826f1084dfcf1f6784c4f32a69e90/bflb-mcu-tool-1.0.1.tar.gz
wget https://files.pythonhosted.org/packages/fd/44/88b46cf8af1a9923d1e61c6daa22f7275d99c1a696e61d3ca3e1ba9e7229/bflb-mcu-tool-1.0.2.tar.gz
wget https://files.pythonhosted.org/packages/f2/60/3cd36586415fe054ead9f700494ef97a1eff496bd7ba385c0c4d4c1278a6/bflb-mcu-tool-1.0.3.tar.gz
wget https://files.pythonhosted.org/packages/6e/7f/878711ab45f09c59a213eae0324a77e9cde59d23900f20da843310637d28/bflb-mcu-tool-1.0.4.tar.gz
wget https://files.pythonhosted.org/packages/6e/5d/2123790253d65715e2218843c94afef049c8c13dd3973d6cd792889cff88/bflb-mcu-tool-1.0.5.tar.gz
wget https://files.pythonhosted.org/packages/39/2e/077741cf1118fb011af9c62155f18f818d06a6d722f0d004f8e6c7db7450/bflb-mcu-tool-1.0.6.tar.gz
wget https://files.pythonhosted.org/packages/df/cc/f01e95f0d982d017daa2baecb5744b7e5d0b8aa21fa4e95d1c00377b258f/bflb-mcu-tool-1.0.7.tar.gz
wget https://files.pythonhosted.org/packages/79/78/c5c6f557d2a280c8c4bd7ec6cf8520b908bc9c5d0e8df01e7db3e1f7d1c5/bflb-mcu-tool-1.6.0.tar.gz
wget https://files.pythonhosted.org/packages/43/33/626aecfc67bcae9ddbd8a35576669d37b6dfde7096e4eea8d15db312ecc8/bflb-mcu-tool-1.6.2.tar.gz
wget https://files.pythonhosted.org/packages/fa/0b/b6e7ed148eda8130530e947739956e54394b6293e49fc26c4bf3a3ffc366/bflb-mcu-tool-1.6.5.tar.gz
wget https://files.pythonhosted.org/packages/a5/57/ab4a45ca3e7736c415f28502db6d897256332521025a52872b534d288207/bflb-mcu-tool-1.6.8.tar.gz
wget https://files.pythonhosted.org/packages/4b/9b/17c7b18505c341757759fae2ebe6e69fa1e40d4d51c9faade922c8df5f64/bflb-mcu-tool-1.7.1.tar.gz
wget https://files.pythonhosted.org/packages/c9/e1/a31fd8e26e9179674a2cfaf677fedaa58413b30811313c3cc7c4b7666dd8/bflb-mcu-tool-1.7.1.post1.tar.gz
wget https://files.pythonhosted.org/packages/65/d2/a2e5f03435525c6acb0e6d50d49f65f09601ec82f3f92311e379e7b8b0f4/bflb-mcu-tool-1.7.5.tar.gz
wget https://files.pythonhosted.org/packages/37/2f/8c4c68f327785083981126e6405da731d614b02c395a9d1371690348eaf8/bflb-mcu-tool-1.7.6.tar.gz
wget https://files.pythonhosted.org/packages/0f/4b/c42d1a7490ab81b55a51ca45403224e889f11cd6738f0e2ea23b9ed28a3c/bflb-mcu-tool-1.7.6.post2.tar.gz
wget https://files.pythonhosted.org/packages/e3/19/a517bfa77916fd50dd52ce36124a96f12a0ea24a31e6226386b0a2e83339/bflb-mcu-tool-1.8.0.tar.gz
wget https://files.pythonhosted.org/packages/d6/91/55e7075447f70fcd27eab1f6afb12744f91c18ed54398b80f8a4fd7d2d00/bflb-mcu-tool-1.8.1.tar.gz
wget https://files.pythonhosted.org/packages/ef/2c/f7a96f39ccda75c3c8caed0a81e8d76d31dbda8f392877326854769d087d/bflb-mcu-tool-1.8.2.tar.gz
wget https://files.pythonhosted.org/packages/d3/e1/f8dec8a6cb938f83ec064cb18e9753be9697042dbf3204b02024571036fc/bflb-mcu-tool-1.8.3.tar.gz
wget https://files.pythonhosted.org/packages/f3/68/132b95fb5499449ddf754c506b296f101d4bd85be044d2cd3ed6e0209190/bflb-mcu-tool-1.8.4.tar.gz
wget https://files.pythonhosted.org/packages/c1/69/5a6b3d09338c65a143f6e48b6fc624d44db26c530c50d08097c1fd5e7232/bflb-mcu-tool-1.8.6.tar.gz
wget https://files.pythonhosted.org/packages/60/c3/17068f422646fdafe7b9787aa319f0b2fd446c32b143aa04f3f939aca36f/bflb-mcu-tool-1.8.7.tar.gz
wget https://files.pythonhosted.org/packages/7c/28/55bf326ed81562e069503fbc7f74354f492c5d3cedf6ee41c00ef37d047d/bflb-mcu-tool-1.8.9.tar.gz

mkdir bflb-mcu-tool
cd bflb-mcu-tool
git init .
git checkout -b main
../build_release_commit.sh 1.0.0 2021-03-09T12:00:00+0000
../build_release_commit.sh 1.0.1 2021-03-10T12:00:00+0000
../build_release_commit.sh 1.0.2 2021-03-12T12:00:00+0000
../build_release_commit.sh 1.0.3 2021-03-18T12:00:00+0000
../build_release_commit.sh 1.0.4 2021-03-22T12:00:00+0000
../build_release_commit.sh 1.0.5 2021-03-23T12:00:00+0000
../build_release_commit.sh 1.0.6 2021-04-08T12:00:00+0000
../build_release_commit.sh 1.0.7 2021-05-13T12:00:00+0000
../build_release_commit.sh 1.6.0 2021-08-17T12:00:00+0000
../build_release_commit.sh 1.6.2 2021-09-15T12:00:00+0000
../build_release_commit.sh 1.6.5 2021-12-15T12:00:00+0000
../build_release_commit.sh 1.6.8 2022-02-13T12:00:00+0000
../build_release_commit.sh 1.7.1 2022-04-13T12:00:00+0000
../build_release_commit.sh 1.7.1.post1 2022-04-14T12:00:00+0000
../build_release_commit.sh 1.7.5 2022-07-05T12:00:00+0000
../build_release_commit.sh 1.7.6 2022-08-10T12:00:00+0000
../build_release_commit.sh 1.7.6.post2 2022-08-10T13:00:00+0000
../build_release_commit.sh 1.8.0 2022-09-02T12:00:00+0000
../build_release_commit.sh 1.8.1 2022-11-25T12:00:00+0000
../build_release_commit.sh 1.8.2 2023-02-02T12:00:00+0000
../build_release_commit.sh 1.8.3 2023-02-24T12:00:00+0000
../build_release_commit.sh 1.8.4 2023-04-13T12:00:00+0000
../build_release_commit.sh 1.8.6 2023-09-12T12:00:00+0000
../build_release_commit.sh 1.8.7 2023-11-22T12:00:00+0000
../build_release_commit.sh 1.8.9 2024-05-07T09:12:02+0000

## after update
# git push
# git push tag [insert tag number here]