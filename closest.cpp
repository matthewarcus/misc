// Demo of divide and conquer closest points algorithm
// from Coursera Algorithms course by Tim Roughgarden 2014.

// Copyright (c) Matthew Arcus 2014
// Licenced for any use whatsoever.
// Please attribute.

// Compile with eg. "g++ -Wall -O2 closest.cpp -o closest"
// Usage: closest [-r] [-p] [-t threshold] [-test] npoints
//  -r: randomize at startup
//  -p: print point set
//  -t: threshold size for switching to brute force, default 0
//  -test: loop checking various randomly generated datasets against brute force
//  npoints: the number of point to generate.

#include <vector>
#include <iostream>
#include <algorithm>
#include <limits>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <time.h>

using namespace std;

double infinity = numeric_limits<double>::infinity();

struct Point
{
  Point(double x_, double y_) : x(x_), y(y_) {}
  // NB: this is the Euclidean distance squared.
  // We use this for comparisons and only take square roots when necessary.
  static double dist2(const Point &p1, const Point &p2) {
    double dx = p2.x-p1.x;
    double dy = p2.y-p1.y;
    return dx*dx+dy*dy;
  }
  double x;
  double y;
};

// This should be wrapped inside a proper class of course.
vector<Point> points;

// Pointer to member template handy for dealing with the two orientations
template<double Point::*xf, double Point::*yf>
bool cmp(int p1, int p2) {
  return 
    points[p1].*xf < points[p2].*xf ||
    (points[p1].*xf == points[p2].*xf && points[p1].*yf < points[p2].*yf);
}

bool cmpx(int p1, int p2) {
  return cmp<&Point::x, &Point::y>(p1,p2);
}

bool cmpy(int p1, int p2) {
  return cmp<&Point::y, &Point::x>(p1,p2);
}

// Brute force solution.
double closest0(const int *px, int size)
{
  double dist = infinity;
  for (int i = 0; i < size-1; i++) {
    for (int j = i+1; j < size; j++) {
      int p1 = px[i];
      int p2 = px[j];
      double d = Point::dist2(points[p1],points[p2]);
      if (d < dist) {
	dist = d;
      }
    }
  }
  return dist;
}

// Problems below this size, use brute force, configurable.
int thresh = 0;

// Maximum number of time round inner loop of edge strip test.
int maxloops = 0;

// Main function, returns distance squared of closest points
// Templated on member accessors so we can use easily, both x-wise and y-wise.

template<double Point::*xf, double Point::*yf>
double closest(const int *px, const int *py, int size)
{
  if (size <= 1) return infinity;
  if (size <= thresh) return closest0(px, size);

  int mid = size/2;
  int p0 = px[mid]; // The index of the pivot point.

  double dist = infinity;

  {
    // Recursive calls. Note that we use both x and y in
    // comparison so we really are splitting input in
    // half, even if we duplicate x coordinates.
    // We could use Vector::reserve to pre-allocate vectors
    vector<int> tmp1;
    vector<int> tmp2;
    for (int i = 0; i < size; i++) {
      int p = py[i];
      if (cmp<xf,yf>(p,p0)) {
	tmp1.push_back(p);
      } else {
	tmp2.push_back(p);
      }
    }
    // Check subarray size
    assert((int)tmp1.size() == mid);
    assert((int)tmp2.size() == size-mid);
    // Recurse, swapping accessors and the x and y arrays.
    double dist1 = closest<yf,xf>(&tmp1[0], px, mid);
    double dist2 = closest<yf,xf>(&tmp2[0], px+mid, size-mid);

    dist = min(dist1,dist2);
  }

  // Now find all the points in the central strip, sorted by y
  {
    vector<int> tmp;
    double x0 = points[p0].*xf; // The position of central line
    double delta = sqrt(dist);  // Get half-strip width
    for (int i = 0; i < size; i++) {
      int p = py[i];
      double x = points[p].*xf;
      if (x >= x0-delta && x <= x0+delta) {
	tmp.push_back(p);
      }
    };
    int npoints = tmp.size();
    for (int i = 0; i < npoints-1; i++) {
      const Point &p1 = points[tmp[i]];
      int loops = 0;
      for (int j= i+1; j < npoints; j++) {
	const Point &p2 = points[tmp[j]];
	// Ordered by y, so break if distance too long
	if (p2.*yf - p1.*yf > delta) break;
	// We could check if p2 is in the other half and
	// save a comparison if it isn't.
	double d = Point::dist2(p1,p2);
	if (d < dist) dist = d;
	// Keep track of our loop count
	loops++;
	if (loops > maxloops) {
	  // Biggest I've seen here is 4
	  cerr << "Loops now " << loops << "\n";
	  maxloops = loops;
	}
      }
    }
  }
  return dist;
}

int main(int argc, char *argv[])
{
  bool test = false;
  bool randomize = false;
  bool printpoints = false;
  int type = 0;
  const char *progname = argv[0];
  argc--; argv++;
  while (argc > 0) {
    if (strcmp(argv[0], "-test") == 0) {
      test = true;
      argc--; argv++;
    } else if (strcmp(argv[0], "-t") == 0) {
      argc--; argv++;
      thresh = atoi(argv[0]);
      argc--; argv++;
    } else if (strcmp(argv[0], "-type") == 0) {
      argc--; argv++;
      type = atoi(argv[0]);
      argc--; argv++;
    } else if (strcmp(argv[0], "-r") == 0) {
      argc--; argv++;
      randomize = true;
    } else if (strcmp(argv[0], "-p") == 0) {
      argc--; argv++;
      printpoints = true;
    } else {
      break;
    }
  }
  if (argc != 1) {
    cerr << "Usage: " << progname << " [-r] [-p] [-t threshold] [-test] npoints\n";
    exit(1);
  }

  int npoints = atoi(argv[0]);

  if (randomize) srand(time(NULL));

  while (true) {
  restart:
    points.clear();
    for (int i = 0; i < npoints; i++) {
      double x = rand()/(double)RAND_MAX;
      double y = rand()/(double)RAND_MAX;
      int ntypes = 11;
      switch (type%ntypes) {
      case 0:
	points.push_back(Point(x,y));
	break;
      case 1:
	points.push_back(Point(1/x,1/y));
	break;
      case 2:
	points.push_back(Point(x,0));
	break;
      case 3:
	points.push_back(Point(0,y));
	break;
      case 4:
	points.push_back(Point(1/x,0));
	break;
      case 5:
	points.push_back(Point(0,1/y));
	break;
      case 6:
	points.push_back(Point(i,0));
	break;
      case 7:
	points.push_back(Point(0,i));
	break;
      case 8:
	points.push_back(Point(i,i));
	break;
      case 9:
	points.push_back(Point(x*x,y*y));
	break;
      case 10:
	points.push_back(Point(1/(x*x),1/(y*y)));
	break;
      default:
	assert(0);
      }
    }
    vector<int> px;
    vector<int> py;
    for (int i = 0; i < (int)points.size(); i++){
      px.push_back(i);
      py.push_back(i);
    }
    sort(px.begin(),px.end(),cmpx);
    sort(py.begin(),py.end(),cmpy);
    for (int i = 0; i < npoints-1; i++) {
      if (points[px[i]].x == points[px[i+1]].x &&
	  points[px[i]].y == points[px[i+1]].y) {
	cerr << "Equal points!\n";
	goto restart;
      }
    }
    type++;
    if (printpoints) {
      for (int i = 0; i < npoints; i++) {
	cerr << points[i].x << " " << points[i].y << "\n";
      }
    }
    //cerr << "Sorted\n";
    double s1 = sqrt(closest<&Point::x, &Point::y>(&px[0],&py[0],npoints));
    if (test) {
      double s2 = sqrt(closest0(&px[0],npoints));
      assert(s1 == s2);
      cout << s1 << " " << s2 << "\n";
    } else {
      cout << s1 << "\n";
      break;
    }
  }
}
