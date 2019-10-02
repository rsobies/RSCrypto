#include "pch.h"
#include "MemoryLeakDetector.h"

MemoryLeakDetector::MemoryLeakDetector()
{
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

	_CrtMemCheckpoint(&state1);
}

void MemoryLeakDetector::makeInitSnapshot() {
	_CrtMemCheckpoint(&state1);
}

MemoryLeakDetector::~MemoryLeakDetector()
{
	_CrtMemState state2;
	_CrtMemState state3;
	_CrtMemCheckpoint(&state2);

	EXPECT_EQ(0, _CrtMemDifference(&state3, &state1, &state2));

	if (_CrtMemDifference(&state3, &state1, &state2))
		_CrtMemDumpStatistics(&state3);
}