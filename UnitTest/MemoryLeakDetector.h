#pragma once
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

/// <summary>
/// class detecting memory leaks
/// it creates memory snapshots and compares them in the destructor
/// </summary>
/// <remarks>
/// in order to provide automatic memory check for each testing method, 
/// set this class as member of Test class
/// </remarks>
class MemoryLeakDetector
{
public:

	/// <summary>
	/// constructor makes first memory snapshot
	/// </summary>
	MemoryLeakDetector();
	
	/// <summary>
	/// compares memory snaspshots
	/// </summary>
	~MemoryLeakDetector();

	/// <summary>
	/// make first snapshot
	/// </summary>
	void makeInitSnapshot();

private:

	/// <summary>
	/// member holding first snapshot
	/// </summary>
	_CrtMemState state1;
};

