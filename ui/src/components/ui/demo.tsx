import { HoverButton } from "@/components/ui/hover-glow-button";

const DemoOne = () => {
  return (
    <HoverButton
      glowColor="#00ffc3"
      backgroundColor="#000"
      textColor="#ffffff"
      hoverTextColor="#67e8f9"
      className="shadow-lg"
    >
      Hover Me!
    </HoverButton>
  );
};

export { DemoOne };
