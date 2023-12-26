//============================================================================
// Name        : OpenSSL.cpp
// Author      :
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "aes.h"

using namespace std;


int aesTest() {


	unsigned char* key = (unsigned char*)"0123456789abcdef";
	//unsigned char* text = (unsigned char*)"My secret message";

	std::string txt = "In this project, we will explore the game-playing of Gobblet, Gobblet is an abstract gameplayed on a 4x4 grid with each of the two players having twelve pieces that can nest ontop of one another to create three stacks of four pieces.Your goal in Gobblet is to place four of your pieces in a horizontal, vertical, or diagonalrow. Your pieces start nested off the board. On a turn, you either play one exposedpiece from your three off-the-board piles or move one piece on the board to any otherspot on the board where it fits. A larger piece can cover any smaller piece. A piecebeing played from off the board may not cover an opponent's piece unless it's in a rowwhere your opponent has three of his color.Your memory is tested as you try to remember which color one of your larger pieces iscovering before you move it. As soon as a player has four like-colored pieces in a row,he wins — except in one case: If you lift your piece and reveal an opponent's piece thatfinishes a four-in-a-row, you don't immediately lose; you can't return the piece to itsstarting location, but if you can place it over one of the opponent's three other pieces inthat row, the game continues..Components16-square playing board12 white Gobblets12 black GobbletsGame rules: RULES OF THE GAMEVideo: https://www.youtube.com/watch?v=aSaAjQY8_b0The GUIYou will need to create a GUI that allows for human vs. human, human vs. computer,and computer vs. computer gameplay. The GUI must include the following mainfeatures:1. Board: Display the current game board and the current pieces on the board.2. Move input: Allow human players to input their moves by clicking on the board3. Game status: Whose turn it is, and if the game is over.4. Game options: Allow players to choose different game modes (e.g., human vs.human, human vs. computer, computer vs. computer), choose the AI playerdifficulty level (for each AI player), and start/restart a new game.5. The Project can be built using any programming language and framework of yourchoice.Game Playing Algorithms1. The minimax algorithm: a basic search algorithm that examines all possible moves froma given position and selects the move that leads to the best outcome for the currentplayer2. Alpha-beta pruning: an improvement on the minimax algorithm that can reduce thenumber of nodes that need to be searched.3. Alpha-beta pruning with iterative deepening (depth is increased iteratively in the searchtree until the timing constraints are violated)HeuristicsUse at least one heuristic, you need to add the heuristic description and approximations taken inyour documentation, You can also feel free to add more heuristics.Collaboration● Teams of 5-9 maximum.● GitHub must be used.● The GitHub repo must include a README file that illustrates all the project features andincludes a user manual.● Clear commits and comments for each team member are mandatory, to show thecollaboration.● The GitHub repo must be private till the submission date.PlagiarismYou cannot copy code / external work and claim it as yours (even with slight modifications likechanging variable names). Plagiarism will not be tolerated. Your work will be checked forplagiarism:● Manually.● Using software tools.";

	unsigned char* text = (unsigned char*)txt.data();

	int text_len = strlen((const char*)text);

	unsigned char* cipher = new unsigned char[((text_len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE)];

	AES_Encrypt(text, text_len, key, cipher);

	int cipher_len = (text_len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

	unsigned char* plaintext = new unsigned char[(cipher_len/AES_BLOCK_SIZE) * AES_BLOCK_SIZE];


	for(int i = 0; i < cipher_len; i++){
		printf("%02x ", cipher[i]);
	}

	for(int i = 0; i < cipher_len; i++){
		printf("%c", cipher[i]);
	}
	cout<<endl;

	printf("\n");

	cout<<cipher_len<<endl;


	int plaintext_len = AES_Decrypt(cipher, cipher_len, key, plaintext);
	cout<<plaintext_len<<endl;

	//plaintext_len = ((cipher_len/AES_BLOCK_SIZE - 1) * AES_BLOCK_SIZE)+1;

	for(int i = 0; i < plaintext_len; i++){
		printf("%c", plaintext[i]);

//		cout << plaintext << endl;

	}

	printf("\n");

	delete[] cipher;
	delete[] plaintext;

    return 0;
}


int AES_Encrypt(unsigned char* text, int text_len, unsigned char* key, unsigned char* cipher){


	int cipher_len = 0;
	int len = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if(!ctx){
		cout << "Error: EVP_CIPHER_CTX_new()" << endl;
		exit(-1);
	}

	if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL)){
		cout << "Error: EVP_CIPHER_CTX_new()" << endl;
		exit(-1);
	}

	if(!EVP_EncryptUpdate(ctx, cipher, &len, text, text_len)){
		cout << "Error: EVP_CIPHER_CTX_new()" << endl;
		exit(-1);
	}

	cipher_len += len;

	if(!EVP_EncryptFinal_ex(ctx, cipher + len, &len)){
		cout << "Error: EVP_CIPHER_CTX_new()" << endl;
		exit(-1);
	}

	cipher_len += len;

	EVP_CIPHER_CTX_free(ctx);


	return cipher_len;
}

int AES_Decrypt(unsigned char* cipher, int cipher_len, unsigned char* key, unsigned char* text){


	int text_len = 0;
	int len = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if(!ctx){
		cout << "Error: EVP_CIPHER_CTX_new()" << endl;
		exit(-1);
	}

	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL)){
		cout << "Error: EVP_DecryptInit_ex()" << endl;
		exit(-1);
	}

	if(!EVP_DecryptUpdate(ctx, text, &len, cipher, cipher_len)){
		cout << "Error: EVP_DecryptUpdate()" << endl;
		exit(-1);
	}

	text_len += len;

	if(!EVP_DecryptFinal_ex(ctx, text + len, &len)){
		cout << "Error: EVP_DecryptFinal_ex()" << endl;
		exit(-1);
	}

	text_len += len;

	EVP_CIPHER_CTX_free(ctx);


	return text_len;
}
