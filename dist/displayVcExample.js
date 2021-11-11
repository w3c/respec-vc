/**
 * Displays a Verifiable Credential example given an element that contains
 * PRE tags and an elementClass to match against and display.
 */
function displayVcExample(element, elementClass) {
  // find all PRE sibling elements in an example block
  const examples = element.parentElement.querySelectorAll('pre');
  // display the provided elementClass, hide all other PRE blocks
  for(example of examples) {
    if(example.classList.contains(elementClass)) {
      example.style.display = 'block';
    } else {
      example.style.display = 'none';
    }
  }
}

window.displayVcExample = displayVcExample;
